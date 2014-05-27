import ctypes

def delete_content(content):
	ns = ctypes.c_char_p(content.namespace)
	container_id = ctypes.c_char_p(content.container_id)
	content_name = ctypes.c_char_p(content.name)
	lib = ctypes.cdll.LoadLibrary("librulesmotorpy2c.so")
	lib.motor_delete_content(ns, container_id, content_name)
