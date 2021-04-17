
linux:
	bash ./scripts/build.sh linux
mac:
	bash ./scripts/build.sh mac
windows:
	bash ./scripts/build.sh windows
alpine:
	bash ./scripts/build.sh alpine
all:
	bash ./scripts/build.sh all
clean:
	rm -rf dist/*