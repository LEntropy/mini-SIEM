.PHONY: test demo
test:
	python tests/test_sources.py
	python tests/test_detect.py
	python tests/test_respond.py
	python tests/test_report.py
	python tests/test_luretrace.py
demo:
	python demo.py
