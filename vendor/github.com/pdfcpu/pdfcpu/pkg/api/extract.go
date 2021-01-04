/*
	Copyright 2019 The pdfcpu Authors.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package api

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/log"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pkg/errors"
)

// ExtractImages dumps embedded image resources from rs into outDir for selected pages.
func ExtractImages(rs io.ReadSeeker, outDir, fileName string, selectedPages []string, conf *pdfcpu.Configuration) error {
	if rs == nil {
		return errors.New("pdfcpu: ExtractImages: Please provide rs")
	}
	if conf == nil {
		conf = pdfcpu.NewDefaultConfiguration()
	}

	fromStart := time.Now()
	ctx, durRead, durVal, durOpt, err := readValidateAndOptimize(rs, conf, fromStart)
	if err != nil {
		return err
	}

	if err := ctx.EnsurePageCount(); err != nil {
		return err
	}

	fromWrite := time.Now()
	pages, err := PagesForPageSelection(ctx.PageCount, selectedPages, true)
	if err != nil {
		return err
	}

	fileName = strings.TrimSuffix(filepath.Base(fileName), ".pdf")

	for i, v := range pages {
		if !v {
			continue
		}
		ii, err := ctx.ExtractPageImages(i)
		if err != nil {
			return err
		}
		for _, img := range ii {
			outFile := filepath.Join(outDir, fmt.Sprintf("%s_%d_%s.%s", fileName, i, img.Name, img.Type))
			log.CLI.Printf("writing %s\n", outFile)
			w, err := os.Create(outFile)
			if err != nil {
				return err
			}
			if _, err = io.Copy(w, img); err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
		}
	}

	durWrite := time.Since(fromWrite).Seconds()
	durTotal := time.Since(fromStart).Seconds()
	log.Stats.Printf("XRefTable:\n%s\n", ctx)
	pdfcpu.TimingStats("write images", durRead, durVal, durOpt, durWrite, durTotal)

	return nil
}

// ExtractImagesFile dumps embedded image resources from inFile into outDir for selected pages.
func ExtractImagesFile(inFile, outDir string, selectedPages []string, conf *pdfcpu.Configuration) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()
	log.CLI.Printf("extracting images from %s into %s/ ...\n", inFile, outDir)
	return ExtractImages(f, outDir, filepath.Base(inFile), selectedPages, conf)
}

// ExtractFonts dumps embedded fontfiles from rs into outDir for selected pages.
func ExtractFonts(rs io.ReadSeeker, outDir, fileName string, selectedPages []string, conf *pdfcpu.Configuration) error {
	if rs == nil {
		return errors.New("pdfcpu: ExtractFonts: Please provide rs")
	}
	if conf == nil {
		conf = pdfcpu.NewDefaultConfiguration()
	}

	fromStart := time.Now()
	ctx, durRead, durVal, durOpt, err := readValidateAndOptimize(rs, conf, fromStart)
	if err != nil {
		return err
	}

	if err := ctx.EnsurePageCount(); err != nil {
		return err
	}

	fromWrite := time.Now()
	pages, err := PagesForPageSelection(ctx.PageCount, selectedPages, true)
	if err != nil {
		return err
	}

	fileName = strings.TrimSuffix(filepath.Base(fileName), ".pdf")

	for i, v := range pages {
		if !v {
			continue
		}
		ff, err := ctx.ExtractPageFonts(i)
		if err != nil {
			return err
		}
		for _, f := range ff {
			outFile := filepath.Join(outDir, fmt.Sprintf("%s_%s.%s", fileName, f.Name, f.Type))
			log.CLI.Printf("writing %s\n", outFile)
			w, err := os.Create(outFile)
			if err != nil {
				return err
			}
			if _, err = io.Copy(w, f); err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
		}
	}

	durWrite := time.Since(fromWrite).Seconds()
	durTotal := time.Since(fromStart).Seconds()
	log.Stats.Printf("XRefTable:\n%s\n", ctx)
	pdfcpu.TimingStats("write fonts", durRead, durVal, durOpt, durWrite, durTotal)
	return nil
}

// ExtractFontsFile dumps embedded fontfiles from inFile into outDir for selected pages.
func ExtractFontsFile(inFile, outDir string, selectedPages []string, conf *pdfcpu.Configuration) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()
	log.CLI.Printf("extracting fonts from %s into %s/ ...\n", inFile, outDir)
	return ExtractFonts(f, outDir, filepath.Base(inFile), selectedPages, conf)
}

// ExtractPages generates single page PDF files from rs in outDir for selected pages.
func ExtractPages(rs io.ReadSeeker, outDir, fileName string, selectedPages []string, conf *pdfcpu.Configuration) error {
	if rs == nil {
		return errors.New("pdfcpu: ExtractPages: Please provide rs")
	}
	if conf == nil {
		conf = pdfcpu.NewDefaultConfiguration()
		conf.Cmd = pdfcpu.EXTRACTPAGES
	}

	fromStart := time.Now()
	ctx, durRead, durVal, durOpt, err := readValidateAndOptimize(rs, conf, fromStart)
	if err != nil {
		return err
	}

	if err := ctx.EnsurePageCount(); err != nil {
		return err
	}

	fromWrite := time.Now()
	pages, err := PagesForPageSelection(ctx.PageCount, selectedPages, true)
	if err != nil {
		return err
	}

	fileName = strings.TrimSuffix(filepath.Base(fileName), ".pdf")

	for i, v := range pages {
		if !v {
			continue
		}
		ctxNew, err := ctx.ExtractPage(i)
		if err != nil {
			return err
		}
		outFile := filepath.Join(outDir, fmt.Sprintf("%s_page_%d.pdf", fileName, i))
		log.CLI.Printf("writing %s\n", outFile)
		if err := WriteContextFile(ctxNew, outFile); err != nil {
			return err
		}
	}

	durWrite := time.Since(fromWrite).Seconds()
	durTotal := time.Since(fromStart).Seconds()
	log.Stats.Printf("XRefTable:\n%s\n", ctx)
	pdfcpu.TimingStats("write PDFs", durRead, durVal, durOpt, durWrite, durTotal)
	return nil
}

// ExtractPagesFile generates single page PDF files from inFile in outDir for selected pages.
func ExtractPagesFile(inFile, outDir string, selectedPages []string, conf *pdfcpu.Configuration) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()
	log.CLI.Printf("extracting pages from %s into %s/ ...\n", inFile, outDir)
	return ExtractPages(f, outDir, filepath.Base(inFile), selectedPages, conf)
}

// ExtractContent dumps "PDF source" files from rs into outDir for selected pages.
func ExtractContent(rs io.ReadSeeker, outDir, fileName string, selectedPages []string, conf *pdfcpu.Configuration) error {
	if rs == nil {
		return errors.New("pdfcpu: ExtractContent: Please provide rs")
	}
	if conf == nil {
		conf = pdfcpu.NewDefaultConfiguration()
	}

	fromStart := time.Now()
	ctx, durRead, durVal, durOpt, err := readValidateAndOptimize(rs, conf, fromStart)
	if err != nil {
		return err
	}

	if err := ctx.EnsurePageCount(); err != nil {
		return err
	}

	fromWrite := time.Now()
	pages, err := PagesForPageSelection(ctx.PageCount, selectedPages, true)
	if err != nil {
		return err
	}

	fileName = strings.TrimSuffix(filepath.Base(fileName), ".pdf")

	for p, v := range pages {
		if !v {
			continue
		}
		r, err := ctx.ExtractPageContent(p)
		if err != nil {
			return err
		}
		if r == nil {
			continue
		}
		outFile := filepath.Join(outDir, fmt.Sprintf("%s_Content_page_%d.txt", fileName, p))
		log.CLI.Printf("writing %s\n", outFile)
		f, err := os.Create(outFile)
		if err != nil {
			return err
		}
		if _, err = io.Copy(f, r); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	durWrite := time.Since(fromWrite).Seconds()
	durTotal := time.Since(fromStart).Seconds()
	log.Stats.Printf("XRefTable:\n%s\n", ctx)
	pdfcpu.TimingStats("write content", durRead, durVal, durOpt, durWrite, durTotal)
	return nil
}

// ExtractContentFile dumps "PDF source" files from inFile into outDir for selected pages.
func ExtractContentFile(inFile, outDir string, selectedPages []string, conf *pdfcpu.Configuration) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()
	log.CLI.Printf("extracting content from %s into %s/ ...\n", inFile, outDir)
	return ExtractContent(f, outDir, inFile, selectedPages, conf)
}

// ExtractMetadata dumps all metadata dict entries for rs into outDir.
func ExtractMetadata(rs io.ReadSeeker, outDir, fileName string, conf *pdfcpu.Configuration) error {
	if rs == nil {
		return errors.New("pdfcpu: ExtractMetadata: Please provide rs")
	}
	if conf == nil {
		conf = pdfcpu.NewDefaultConfiguration()
	}

	fromStart := time.Now()
	ctx, durRead, durVal, durOpt, err := readValidateAndOptimize(rs, conf, fromStart)
	if err != nil {
		return err
	}

	fromWrite := time.Now()

	mm, err := ctx.ExtractMetadata()
	if err != nil {
		return err
	}

	if len(mm) > 0 {
		fileName = strings.TrimSuffix(filepath.Base(fileName), ".pdf")
		for _, m := range mm {
			outFile := filepath.Join(outDir, fmt.Sprintf("%s_Metadata_%s_%d_%d.txt", fileName, m.ParentType, m.ParentObjNr, m.ObjNr))
			log.CLI.Printf("writing %s\n", outFile)
			f, err := os.Create(outFile)
			if err != nil {
				return err
			}
			if _, err = io.Copy(f, m); err != nil {
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}

	durWrite := time.Since(fromWrite).Seconds()
	durTotal := time.Since(fromStart).Seconds()
	log.Stats.Printf("XRefTable:\n%s\n", ctx)
	pdfcpu.TimingStats("write metadata", durRead, durVal, durOpt, durWrite, durTotal)
	return nil
}

// ExtractMetadataFile dumps all metadata dict entries for inFile into outDir.
func ExtractMetadataFile(inFile, outDir string, conf *pdfcpu.Configuration) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()
	log.CLI.Printf("extracting metadata from %s into %s/ ...\n", inFile, outDir)
	return ExtractMetadata(f, outDir, filepath.Base(inFile), conf)
}
