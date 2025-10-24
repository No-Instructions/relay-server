# Relay Python SDK

Python client library for interacting with the Relay server.

## Usage

```python
from relay_sdk import DocumentManager

# Get the websocket url for a document.
doc = DocumentManager('http://localhost:8080')
url = doc.get_websocket_url('my-document-id')

# Connect to the document using y_py and ypy_websocket.
# (Based on: https://davidbrochart.github.io/ypy-websocket/usage/client/)
from ypy_websocket import WebsocketProvider
import y_py as Y
from websockets import connect
import asyncio

ydoc = Y.YDoc()

# Simple example: log the array "todolist" to stdout every time it changes.
data = ydoc.get_array("todolist")
def data_changed(event: Y.AfterTransactionEvent):
    print(f"data changed: {data.to_json()}")

data.observe_deep(data_changed)

async with (
    connect(url) as websocket,
    WebsocketProvider(ydoc, websocket),
):
    await asyncio.Future()  # run forever
```

`relay_sdk` is only used to talk directly with the Relay server to obtain a WebSocket URL to pass to a client.
Use a Yjs client like [ypy-websocket](https://davidbrochart.github.io/ypy-websocket/usage/client/) or [pycrdt](https://github.com/jupyter-server/pycrdt)
in conjunction with `relay_sdk` to access the actual Y.Doc data.

## Developing

Developing `relay_sdk` requires the [`uv`](https://docs.astral.sh/uv/) project manager.

To install it on Mac or Liunux, run:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

(See [the docs](https://docs.astral.sh/uv/) for other platforms and more information.)

When using `uv`, you do not need to manage a virtual environment yourself. Instead, you interact with
Python using the `uv` command, which automatically picks up the virtual environment from the location.

To set up the virtual environment for development, run:

```bash
uv sync --dev
```

This installs both the regular dependencies and the development dependencies.

### Tests

Once commands are installed in your virtual environment, you can run them with `uv run`.

To run tests, run:

```bash
uv run pytest
```

This runs the `pytest` command in the virtual environment.

### Formatting

Run `uv run ruff format` to format before committing changes.

## Acknowledgements

This is a fork of the [y-sweet Python SDK](https://github.com/jamsocket/y-sweet) by the folks at Jamsocket.
