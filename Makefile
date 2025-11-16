path = /usr/local/bin/aws-sso

clean:
	rm -f ${path}

help: ${path}
	aws-sso.py | yq -P
list: ${path}
	aws-sso.py -l | yq -P
list-profiles: ${path}
	aws-sso.py -p | yq -P
run: ${path}
	aws-sso.py
run-yq: ${path}
	aws-sso.py | yq -P

serve: ${path}
	aws-sso.py serve

stop: ${path}
	aws-sso.py stop

${path}:
	ln -sf $$(realpath aws-sso.py) ${path}
