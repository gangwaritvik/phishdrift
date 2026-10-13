"""Tier B forms group."""

from tests.html_helpers import feats, isnan, page


def form(action: str | None, inner: str = '<input type="text" name="q">') -> str:
    attr = "" if action is None else f' action="{action}"'
    return f'<form method="post"{attr}>{inner}<input type="submit" value="Go"></form>'


def test_credential_form_posting_to_another_domain():
    html = page(
        form(
            "https://collector.bad-site.biz/post.php",
            '<input type="text" name="email"><input type="password" name="pass">'
            '<input type="hidden" name="token" value="1">',
        )
    )
    f = feats(html)
    assert (f["n_forms"], f["n_password_fields"], f["n_credential_forms"]) == (1, 1, 1)
    assert f["n_form_action_external"] == 1 and f["n_password_forms_external"] == 1
    assert f["n_input_hidden"] == 1 and f["hidden_input_ratio"] == 0.25  # 1 of 4 inputs
    assert f["has_submit_button"] == 1 and f["n_password_outside_form"] == 0


def test_action_kinds():
    html = page(
        form("")
        + form(None)
        + form("   ")
        + form("#")
        + form("#top")
        + form("javascript:void(0)")
        + form("JavaScript:go()")
        + form("mailto:a@b.com")
        + form("/login")
        + form("login.php")
        + form("https://www.example.com/post")
        + form("//shop.example.com/post")
        + form("https://other.org/post")
    )
    f = feats(html)
    assert f["n_forms"] == 13
    assert f["n_form_action_empty"] == 3  # "", missing, blank
    assert f["n_form_action_hash"] == 2
    assert f["n_form_action_js"] == 2
    assert f["n_form_action_mailto"] == 1
    assert f["n_form_action_external"] == 1  # same registrable domain is not external


def test_password_outside_form_and_forms_without_password():
    html = page('<input type="password" name="p"><form action="/x"><input name="q"></form>')
    f = feats(html)
    assert f["n_password_fields"] == 1 and f["n_password_outside_form"] == 1
    assert f["n_credential_forms"] == 0 and f["n_password_forms_external"] == 0


def test_no_inputs_gives_nan_ratio_and_zero_counts():
    f = feats(page())
    assert isnan(f["hidden_input_ratio"])
    assert f["n_forms"] == 0 and f["n_password_fields"] == 0 and f["has_submit_button"] == 0


def test_submit_button_kinds():
    assert feats(page("<form><button>Send</button></form>"))["has_submit_button"] == 1
    assert feats(page('<form><button type="submit">Send</button></form>'))["has_submit_button"] == 1
    assert feats(page('<form><button type="button">Send</button></form>'))["has_submit_button"] == 0
    assert feats(page('<input type="image" src="go.png">'))["has_submit_button"] == 1


def test_sensitive_field_names():
    inner = (
        '<input type="text" name="otp_code">'
        '<input type="tel" placeholder="One time password">'
        '<input type="text" name="card_number">'
        '<input type="text" id="ccnum">'
        '<input type="text" name="cvv">'
        '<input type="password" name="cvc2">'
        '<input type="password" name="upi_pin">'
        '<input type="password" placeholder="Enter MPIN">'
        '<input type="text" name="atm-pin">'
    )
    f = feats(page(form("/x", inner)))
    assert f["n_otp_fields"] == 2
    assert f["n_card_fields"] == 2
    assert f["n_cvv_fields"] == 2
    assert f["n_upi_pin_fields"] == 3


def test_field_name_matching_avoids_common_false_positives():
    inner = (
        '<input type="text" name="pincode">'  # postal code, not a PIN
        '<input type="text" name="discard">'
        '<input type="text" name="hotpot">'
        '<input type="hidden" name="otp">'  # hidden fields are not asked for by the user
        '<input type="checkbox" name="card">'
    )
    f = feats(page(form("/x", inner)))
    assert (f["n_otp_fields"], f["n_card_fields"], f["n_upi_pin_fields"]) == (0, 0, 0)


def test_masked_platforms_count_as_one_domain():
    # Both hosts are hosting platforms: masking makes the page and the action the same domain.
    html = page(form("https://other.web.app/post", '<input type="password" name="p">'))
    f = feats(html, url="https://victim.github.io/login")
    assert f["n_form_action_external"] == 0
    # A real third-party domain is still external.
    html = page(form("https://other.org/post", '<input type="password" name="p">'))
    assert feats(html, url="https://victim.github.io/login")["n_form_action_external"] == 1
