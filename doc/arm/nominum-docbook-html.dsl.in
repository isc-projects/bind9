<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY dbstyle SYSTEM "/usr/local/share/sgml/docbook/dsssl/modular/html/docbook.dsl" CDATA DSSSL>
]>

<style-sheet>
<style-specification use="docbook">
<style-specification-body>

<!-- ;; your stuff goes here... -->

(define %html-prefix% 
  ;; Add the specified prefix to HTML output filenames
  "Bv9ARM.")

(define %use-id-as-filename%
  ;; Use ID attributes as name for component HTML files?
  #t)

(define %root-filename%
  ;; Name for the root HTML document
  "Bv9ARM")

(define %section-autolabel%
  ;; REFENTRY section-autolabel
  ;; PURP Are sections enumerated?
  ;; DESC
  ;; If true, unlabeled sections will be enumerated.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define %html-ext% 
  ;; REFENTRY html-ext
  ;; PURP Default extension for HTML output files
  ;; DESC
  ;; The default extension for HTML output files.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  ".html")

(define nochunks
  ;; REFENTRY nochunks
  ;; PURP Suppress chunking of output pages
  ;; DESC
  ;; If true, the entire source document is formatted as a single HTML
  ;; document and output on stdout.
  ;; (This option can conveniently be set with '-V nochunks' on the 
  ;; Jade command line).
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #f)

(define rootchunk
  ;; REFENTRY rootchunk
  ;; PURP Make a chunk for the root element when nochunks is used
  ;; DESC
  ;; If true, a chunk will be created for the root element, even though
  ;; nochunks is specified. This option has no effect if nochunks is not
  ;; true.
  ;; (This option can conveniently be set with '-V rootchunk' on the 
  ;; Jade command line).
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define html-index
  ;; REFENTRY html-index
  ;; PURP HTML indexing?
  ;; DESC
  ;; Turns on HTML indexing.  If true, then index data will be written
  ;; to the file defined by 'html-index-filename'.  This data can be
  ;; collated and turned into a DocBook index with bin/collateindex.pl.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define html-manifest
  ;; REFENTRY html-manifest
  ;; PURP Write a manifest?
  ;; DESC
  ;; If not '#f' then the list of HTML files created by the stylesheet
  ;; will be written to the file named by 'html-manifest-filename'.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define (chunk-element-list)
  (list (normalize "preface")
	(normalize "chapter")
	(normalize "appendix") 
	(normalize "article")
	(normalize "glossary")
	(normalize "bibliography")
	(normalize "index")
	(normalize "colophon")
	(normalize "setindex")
	(normalize "reference")
	(normalize "refentry")
	(normalize "part")
	(normalize "book") ;; just in case nothing else matches...
	(normalize "set")  ;; sets are definitely chunks...
	))

</style-specification-body>
</style-specification>
<external-specification id="docbook" document="dbstyle">
</style-sheet>
