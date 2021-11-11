/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_IMPL
#define SECP256K1_MODULE_MUSIG_KEYAGG_IMPL

#include "keyagg.h"


static void secp256k1_point_save(unsigned char *data, secp256k1_ge *ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(data, &s, sizeof(s));
    } else {
        VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(data, &ge->x);
        secp256k1_fe_get_b32(data + 32, &ge->y);
    }
}

static void secp256k1_point_load(secp256k1_ge *ge, const unsigned char *data) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation as conversion is very fast. */
        secp256k1_ge_storage s;
        memcpy(&s, data, sizeof(s));
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, data);
        secp256k1_fe_set_b32(&y, data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
}

static const unsigned char secp256k1_musig_keyagg_cache_magic[4] = { 0xf4, 0xad, 0xbb, 0xdf };

/* A keyagg cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate (and potentially tweaked) public key
 * - 32 byte X-coordinate of "second" public key (0 if not present)
 * - 32 byte hash of all public keys
 * - 1 byte indicating if the public key is tweaked and if so, also the parity
 *   of the internal key
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity */
static void secp256k1_keyagg_cache_save(secp256k1_musig_keyagg_cache *cache, secp256k1_keyagg_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, secp256k1_musig_keyagg_cache_magic, 4);
    ptr += 4;
    secp256k1_point_save(ptr, &cache_i->pk);
    ptr += 64;
    secp256k1_fe_get_b32(ptr, &cache_i->second_pk_x);
    ptr += 32;
    memmove(ptr, cache_i->pk_hash, 32);
    ptr += 32;
    *ptr = cache_i->is_tweaked;
    *ptr |= cache_i->internal_key_parity << 1;
    ptr += 1;
    secp256k1_scalar_get_b32(ptr, &cache_i->tweak);
}

static int secp256k1_keyagg_cache_load(const secp256k1_context* ctx, secp256k1_keyagg_cache_internal *cache_i, const secp256k1_musig_keyagg_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_musig_keyagg_cache_magic, 4) == 0);
    ptr += 4;
    secp256k1_point_load(&cache_i->pk, ptr);
    ptr += 64;
    secp256k1_fe_set_b32(&cache_i->second_pk_x, ptr);
    ptr += 32;
    cache_i->pk_hash = ptr;
    ptr += 32;
    cache_i->is_tweaked = *ptr & 1;
    cache_i->internal_key_parity = *ptr & 2;
    ptr += 1;
    secp256k1_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg list")||SHA256("KeyAgg list"). */
static void secp256k1_musig_keyagglist_sha256(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0xb399d5e0ul;
    sha->s[1] = 0xc8fff302ul;
    sha->s[2] = 0x6badac71ul;
    sha->s[3] = 0x07c5b7f1ul;
    sha->s[4] = 0x9701e2eful;
    sha->s[5] = 0x2a72ecf8ul;
    sha->s[6] = 0x201a4c7bul;
    sha->s[7] = 0xab148a38ul;
    sha->bytes = 64;
}

/* Computes pk_hash = SHA256(pk[0], ..., pk[np-1]) */
static int secp256k1_musig_compute_pk_hash(const secp256k1_context *ctx, unsigned char *pk_hash, const secp256k1_xonly_pubkey * const* pk, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_musig_keyagglist_sha256(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, pk[i])) {
            return 0;
        }
        secp256k1_sha256_write(&sha, ser, 32);
    }
    secp256k1_sha256_finalize(&sha, pk_hash);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg coefficient")||SHA256("KeyAgg coefficient"). */
static void secp256k1_musig_keyaggcoef_sha256(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0x6ef02c5aul;
    sha->s[1] = 0x06a480deul;
    sha->s[2] = 0x1f298665ul;
    sha->s[3] = 0x1d1134f2ul;
    sha->s[4] = 0x56a0b063ul;
    sha->s[5] = 0x52da4147ul;
    sha->s[6] = 0xf280d9d4ul;
    sha->s[7] = 0x4484be15ul;
    sha->bytes = 64;
}

/* Compute KeyAgg coefficient which is constant 1 for the second pubkey and
 * SHA256(pk_hash, x) where pk_hash is the hash of public keys otherwise. second_pk_x
 * can be 0 in case there is no second_pk. Assumes both field elements x and
 * second_pk_x are normalized. */
static void secp256k1_musig_keyaggcoef_internal(secp256k1_scalar *r, const unsigned char *pk_hash, const secp256k1_fe *x, const secp256k1_fe *second_pk_x) {
    secp256k1_sha256 sha;
    unsigned char buf[32];

    if (secp256k1_fe_cmp_var(x, second_pk_x) == 0) {
        secp256k1_scalar_set_int(r, 1);
    } else {
        secp256k1_musig_keyaggcoef_sha256(&sha);
        secp256k1_sha256_write(&sha, pk_hash, 32);
        secp256k1_fe_get_b32(buf, x);
        secp256k1_sha256_write(&sha, buf, 32);
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(r, buf, NULL);
    }

}

/* Assumes both field elements x and second_pk_x are normalized. */
static void secp256k1_musig_keyaggcoef(secp256k1_scalar *r, const secp256k1_keyagg_cache_internal *cache_i, secp256k1_fe *x) {
    secp256k1_musig_keyaggcoef_internal(r, cache_i->pk_hash, x, &cache_i->second_pk_x);
}

typedef struct {
    const secp256k1_context *ctx;
    /* pk_hash is the hash of the public keys */
    unsigned char pk_hash[32];
    const secp256k1_xonly_pubkey * const* pks;
    secp256k1_fe second_pk_x;
} secp256k1_musig_pubkey_agg_ecmult_data;

/* Callback for batch EC multiplication to compute pk_hash_0*P0 + pk_hash_1*P1 + ...  */
static int secp256k1_musig_pubkey_agg_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_pubkey_agg_ecmult_data *ctx = (secp256k1_musig_pubkey_agg_ecmult_data *) data;
    int ret;
    ret = secp256k1_xonly_pubkey_load(ctx->ctx, pt, ctx->pks[idx]);
    /* pubkey_load can't fail because the same pks have already been loaded (and
     * we test this) */
    VERIFY_CHECK(ret);
    secp256k1_musig_keyaggcoef_internal(sc, ctx->pk_hash, &pt->x, &ctx->second_pk_x);
    return 1;
}

int secp256k1_musig_pubkey_agg(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, secp256k1_xonly_pubkey *agg_pk, secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_xonly_pubkey * const* pubkeys, size_t n_pubkeys) {
    secp256k1_musig_pubkey_agg_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    if (agg_pk != NULL) {
        memset(agg_pk, 0, sizeof(*agg_pk));
    }
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;
    /* No point on the curve has an X coordinate equal to 0 */
    secp256k1_fe_set_int(&ecmult_data.second_pk_x, 0);
    for (i = 1; i < n_pubkeys; i++) {
        secp256k1_ge pt;
        if (!secp256k1_xonly_pubkey_load(ctx, &pt, pubkeys[i])) {
            return 0;
        }
        if (secp256k1_memcmp_var(pubkeys[0], pubkeys[i], sizeof(*pubkeys[0])) != 0) {
            ecmult_data.second_pk_x = pt.x;
            break;
        }
    }

    if (!secp256k1_musig_compute_pk_hash(ctx, ecmult_data.pk_hash, pubkeys, n_pubkeys)) {
        return 0;
    }
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_musig_pubkey_agg_callback, (void *) &ecmult_data, n_pubkeys)) {
        /* The current implementation of ecmult_multi_var makes this code unreachable with tests. */
        return 0;
    }
    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    /* The resulting public key is infinity with negligible probability */
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&pkp));
    if (keyagg_cache != NULL) {
        secp256k1_keyagg_cache_internal cache_i = { 0 };
        cache_i.pk = pkp;
        cache_i.second_pk_x = ecmult_data.second_pk_x;
        cache_i.pk_hash = ecmult_data.pk_hash;
        secp256k1_keyagg_cache_save(keyagg_cache, &cache_i);
    }

    secp256k1_extrakeys_ge_even_y(&pkp);
    if (agg_pk != NULL) {
        secp256k1_xonly_pubkey_save(agg_pk, &pkp);
    }
    return 1;
}

int secp256k1_musig_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, const unsigned char *tweak32, secp256k1_musig_keyagg_cache *keyagg_cache) {
    secp256k1_keyagg_cache_internal cache_i;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(tweak32 != NULL);

    if(!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    /* This function can only be called once because otherwise signing would not
     * succeed */
    ARG_CHECK(cache_i.is_tweaked == 0);

    cache_i.internal_key_parity = secp256k1_extrakeys_ge_even_y(&cache_i.pk);
    secp256k1_scalar_set_b32(&cache_i.tweak, tweak32, &overflow);
    if(overflow || !secp256k1_eckey_pubkey_tweak_add(&ctx->ecmult_ctx, &cache_i.pk, &cache_i.tweak)) {
        return 0;
    }
    cache_i.is_tweaked = 1;
    /* eckey_pubkey_tweak_add fails if cache_i.pk is infinity */
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&cache_i.pk));
    secp256k1_keyagg_cache_save(keyagg_cache, &cache_i);
    if (output_pubkey != NULL) {
        secp256k1_pubkey_save(output_pubkey, &cache_i.pk);
    }
    return 1;
}

#endif
