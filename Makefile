path = /usr/local/bin/aws-sso

clean:
	rm -f ${path}

run: ${path}
	aws-sso

serve: ${path}
	aws-sso start

${path}:
	ln -sf $$(realpath aws-sso.py) ${path}
