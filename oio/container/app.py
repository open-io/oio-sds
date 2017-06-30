from oio.container.backup import ContainerBackup


def create_app(conf=None):
    app = ContainerBackup(conf)
    return app


if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 6002, create_app(),
               use_debugger=True, use_reloader=True)
