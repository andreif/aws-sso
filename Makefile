path = /usr/local/bin/aws-sso

clean:
	rm -f ${path}

run: ${path}
	aws-sso.py

serve: ${path}
	aws-sso.py serve

${path}:
	ln -sf $$(realpath aws-sso.py) ${path}
