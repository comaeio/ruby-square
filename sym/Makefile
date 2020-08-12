.PHONY: build run shell

TAG=as_manticore:latest

build:
	# Do not add local directories to the build context (faster):
	docker build -t ${TAG} - < Dockerfile

run:
	docker run -v $(shell pwd):/devel -it ${TAG}

shell:
	docker exec -it $(shell docker ps -q) bash
