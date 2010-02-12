TCL2TEXKIT = $(srcdir)/../Support/tcl2tex.kit
TCL2TEX = $(TCLKIT) $(TCL2TEXKIT)

TCL_INTERNALS_PDF = TclInternals.pdf
TCL_INTERNALS_HTML = TclInternals/TclInternals.html

TCL_INTERNALS_LATEXSX = Facebook.tex HelloUser.tex

TCL_INTERNALS_HERE = 
TCL_INTERNALS_LATEXS = ../MyTitlepage.sty \
		../titlepage.tex $(TCL_INTERNALS_LATEXSX) $(TCL_INTERNALS_HERE)
TCL_INTERNALS_LATEX = TclInternals.tex
TCL_INTERNALS_IND = TclInternals.ind  
TCL_INTERNALS_IDX = TclInternals.idx  
TCL_INTERNALSBase = TclInternals

CLEANFILES = *.aux *.bbl *.blg *.log TclInternals.pdf \
        *.css *.idx *.ilg *.ind *.toc  $(TCL_INTERNALS_LATEXSX)

%.tex: %.tcl
	$(TCL2TEX) -forinput $@ $<

EXTRA_DIST = $(TCL_INTERNALS_HERE) $(TCL_INTERNALS_LATEX)

pkgdatadir = $(datadir)/$(PACKAGE)/Doc

install-data-hook: $(TCL_INTERNALS_HTML) #$(C_INTERNALS_HTML) 
	$(INSTALL) -d $(DESTDIR)$(pkgdatadir)/TclInternals
	for p in TclInternals/*; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(am__strip_dir) \
	  echo " $(pkgdataDATA_INSTALL) '$$d$$p' '$(DESTDIR)$(pkgdatadir)/TclInternals$$f'"; \
	  $(pkgdataDATA_INSTALL) "$$d$$p" "$(DESTDIR)$(pkgdatadir)/TclInternals/$$f"; \
        done
	
uninstall-hook: 
	for p in $(DESTDIR)$(pkgdatadir)/TclInternals/*; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(am__strip_dir) \
	  echo " rm -f '$(DESTDIR)$(pkgdatadir)/TclInternals$$f'"; \
	  rm -f "$(DESTDIR)$(pkgdatadir)/TclInternals/$$f"; \
        done
	
pkgdata_DATA = $(TCL_INTERNALS_PDF)

noinst_DATA = $(TCL_INTERNALS_HTML)

$(TCL_INTERNALS_PDF) : $(TCL_INTERNALS_LATEX) $(TCL_INTERNALS_LATEXS)
	-ln -s $(srcdir)/../MyTitlepage.sty ./MyTitlepage.sty
	-ln -s $(srcdir)/../titlepage.tex ./titlepage.tex
	-ln -s $(srcdir)/$(TCL_INTERNALS_LATEX) ./$(TCL_INTERNALS_LATEX)
	-ln -s $(srcdir)/../MyPart.sty ./MyPart.sty
	$(PDFLATEX) $(TCL_INTERNALS_LATEX)
	echo '\begin{theindex}' > $(TCL_INTERNALS_IND)
	echo '\item Dummy, 0' >> $(TCL_INTERNALS_IND)
	echo '\end{theindex}' >> $(TCL_INTERNALS_IND)
	$(PDFLATEX) $(TCL_INTERNALS_LATEX)
	$(MAKEINDEX) $(TCL_INTERNALS_IDX)
	$(PDFLATEX) $(TCL_INTERNALS_LATEX)

$(TCL_INTERNALS_HTML) : $(TCL_INTERNALS_PDF)
	-rm -rf $(TCL_INTERNALSBase)
	-mkdir $(TCL_INTERNALSBase)
	$(HTLATEX) $(TCL_INTERNALSBase) "html,2,info" "" \
		"-d$(TCL_INTERNALSBase)/"
	-rm -f zz$(TCL_INTERNALSBase).p* $(TCL_INTERNALSBase).4ct \
		$(TCL_INTERNALSBase).xref $(TCL_INTERNALSBase).4tc tex4ht.fls \
		$(TCL_INTERNALSBase).tmp $(TCL_INTERNALSBase).lg \
		$(TCL_INTERNALSBase).idv $(TCL_INTERNALSBase).dvi \
		$(TCL_INTERNALSBase)*.html

HelloUser.tex : $(top_srcdir)/HelloUser/HelloUser.tcl
	$(TCL2TEX) -forinput $@ $<

Facebook.tex : $(top_srcdir)/Common/Facebook.tcl
	$(TCL2TEX) -forinput $@ $<
