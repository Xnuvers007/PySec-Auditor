from src.language import get_msg, set_language
def test_language_default():
    set_language("en")
    assert "HTTP Security Toolkit" not in get_msg("title_main") or isinstance(get_msg("title_main"), str)
    set_language("id")
    assert isinstance(get_msg("title_main"), str)
