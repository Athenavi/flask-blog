import requests
from flask import Response, request


def proxy_request(target_url):
    try:
        if request.method == 'GET':
            response = requests.get(
                target_url,
                params=request.args,
                headers=dict(request.headers)
            )
        elif request.method == 'POST':
            response = requests.post(
                target_url,
                data=request.get_data(),
                headers=dict(request.headers),
                params=request.args
            )
        elif request.method == 'PUT':
            response = requests.put(
                target_url,
                data=request.get_data(),
                headers=dict(request.headers),
                params=request.args
            )
        elif request.method == 'DELETE':
            response = requests.delete(
                target_url,
                headers=dict(request.headers),
                params=request.args
            )
        else:
            return Response("Method not allowed", status=405)

        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )

    except requests.exceptions.ConnectionError:
        return Response("Backend server is not responding", status=502)
    except Exception as e:
        return Response(f"Proxy error: {str(e)}", status=500)
