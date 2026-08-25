from unittest.mock import Mock

from youtrack_mcp.api.articles import ArticlesClient


def article(article_id: int, summary: str, content: str) -> dict:
    return {
        "id": f"226-{article_id}",
        "idReadable": f"DOC-A-{article_id}",
        "summary": summary,
        "content": content,
        "updated": 1750000000000 + article_id,
        "project": {"id": "0-1", "name": "Документация", "shortName": "DOC"},
    }


def test_list_articles_uses_public_collection_without_unsupported_query():
    client = Mock()
    client.get.return_value = [article(1, "Начало", "Текст")]

    result = ArticlesClient(client).list_articles(top=10, skip=5)

    assert result[0].idReadable == "DOC-A-1"
    client.get.assert_called_once_with(
        "articles",
        params={
            "$top": 10,
            "$skip": 5,
            "fields": "id,idReadable,summary,updated,project(id,name,shortName)",
        },
    )


def test_list_articles_can_use_project_articles_endpoint():
    client = Mock()
    client.get.return_value = []

    ArticlesClient(client).list_articles(project_id="0-1")

    assert client.get.call_args.args[0] == "admin/projects/0-1/articles"


def test_search_articles_matches_cyrillic_in_title_and_content():
    client = Mock()
    client.get.return_value = [
        article(1, "Настройка сервера", "Инструкция для Linux"),
        article(2, "Windows", "Настройка сервера и кодировки UTF-8"),
        article(3, "Другое", "Не подходит"),
    ]

    result = ArticlesClient(client).search_articles("НАСТРОЙКА сервера", top=20)

    assert [item.idReadable for item in result] == ["DOC-A-1", "DOC-A-2"]
    assert all(item.content is None for item in result)
    assert "query" not in client.get.call_args.kwargs["params"]


def test_search_articles_pages_until_it_finds_a_match():
    client = Mock()
    client.get.side_effect = [
        [article(index, f"Статья {index}", "обычный текст") for index in range(42)],
        [article(42, "Нужная статья", "искомая строка")],
    ]

    result = ArticlesClient(client).search_articles("искомая строка", top=1)

    assert [item.idReadable for item in result] == ["DOC-A-42"]
    assert client.get.call_count == 2
    assert client.get.call_args_list[1].kwargs["params"]["$skip"] == 42
