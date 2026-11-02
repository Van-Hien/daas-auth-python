from fastapi import FastAPI
from fastapi.testclient import TestClient

PROBLEM = "application/problem+json"


def test_an_unknown_path_is_404_problem(client: TestClient) -> None:
    response = client.get("/nowhere")
    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM
    assert response.json() == {
        "type": "about:blank",
        "title": "Not Found",
        "status": 404,
    }


def test_a_wrong_method_is_405_problem(client: TestClient) -> None:
    response = client.delete("/health")
    assert response.status_code == 405
    assert response.headers["content-type"] == PROBLEM
    assert response.headers["allow"] == "GET"
    assert response.json()["title"] == "Method Not Allowed"


def test_a_bad_parameter_is_400_problem_without_the_input(app: FastAPI) -> None:
    # A route only for this test: no route of the service takes a body yet.
    @app.get("/test-only")
    def test_only(count: int) -> int:
        return count

    with TestClient(app) as client:
        response = client.get("/test-only", params={"count": "secret-pw"})
    assert response.status_code == 400
    assert response.headers["content-type"] == PROBLEM
    assert response.json()["detail"] == (
        "query.count: Input should be a valid integer, unable to parse string as an integer"
    )
    assert "secret-pw" not in response.text
