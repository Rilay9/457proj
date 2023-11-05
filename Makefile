PYTHON_PATH=/usr/local/bin/python3

.PHONY: all clean

all:
	python3 -m zipapp --python /usr/local/bin/python3 --output rserver server_stuff

clean:
	rm -f rserver
