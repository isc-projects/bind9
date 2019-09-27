;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

((c-mode .
  ((eval .
	 (set (make-local-variable 'directory-of-current-dir-locals-file)
	      (file-name-directory (locate-dominating-file default-directory ".dir-locals.el"))
	      )
	 )
   (eval .
	 (set (make-local-variable 'include-directories)
	      (list

	       ;; top directory
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "./"))

	       ;; libisc
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isc/unix/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isc/pthreads/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isc/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isc"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isc/netmgr"))

	       ;; libdns
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/dns/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/dns"))

	       ;; libisccc
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isccc/include"))

	       ;; libisccfg
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/isccfg/include"))

	       ;; libns
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/ns/include"))

	       ;; libirs
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/irs/include"))

	       ;; libbind9
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "lib/bind9/include"))

	       ;; bin
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/check"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/confgen/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/confgen"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/confgen/include"))	       
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/dig/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/named/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/named/unix/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/rndc/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/dnssec/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/named/include"))
	       (expand-file-name
		(concat directory-of-current-dir-locals-file "bin/rndc/include"))

	       (expand-file-name "/usr/local/opt/openssl@1.1/include")
	       (expand-file-name "/usr/local/opt/libxml2/include/libxml2")
	       (expand-file-name "/usr/local/opt/json-c/include/json-c/")
	       (expand-file-name "/usr/local/include")
	       )
	      )
	 )

   (eval setq flycheck-clang-include-path include-directories)
   (eval setq flycheck-cppcheck-include-path include-directories)
   (eval setq flycheck-gcc-include-path include-directories)
   (eval setq flycheck-clang-args
	 (list
	  "-include"
	  (expand-file-name
	   (concat directory-of-current-dir-locals-file "config.h"))
	  )
	 )
   (eval setq flycheck-gcc-args
	 (list
	  "-include"
	  (expand-file-name
	   (concat directory-of-current-dir-locals-file "config.h"))
	  )
	 )
   (eval setq flycheck-cppcheck-args
	 (list
	  "--enable=all"
	  "--suppress=missingIncludeSystem"
	  (concat "-include=" (expand-file-name
			       (concat directory-of-current-dir-locals-file "config.h")))
	  )
	 )
   )
  ))
