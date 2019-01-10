window.addEventListener("load", function() {
  update();
});

window.addEventListener("resize", function() {
  update();
});

window.a = (s) => document.querySelectorAll(s);
window.q = (s) => document.querySelector(s);

window.parseHtml = (string) => new DOMParser().parseFromString(string, "text/html").body.childNodes[0];

window.escapeHtml = (string) => {
  var matchHtmlRegExp = /["'&<>]/;
  var str = '' + string;
  var match = matchHtmlRegExp.exec(str);

  if (!match) {
    return str;
  }

  var escape;
  var html = '';
  var index = 0;
  var lastIndex = 0;

  for (index = match.index; index < str.length; index++) {
    switch (str.charCodeAt(index)) {
      case 34: // "
        escape = '&quot;';
        break;
      case 38: // &
        escape = '&amp;';
        break;
      case 39: // '
        escape = '&#39;';
        break;
      case 60: // <
        escape = '&lt;';
        break;
      case 62: // >
        escape = '&gt;';
        break;
      default:
        continue;
    }

    if (lastIndex !== index) {
      html += str.substring(lastIndex, index);
    }

    lastIndex = index + 1;
    html += escape;
  }

  return lastIndex !== index
    ? html + str.substring(lastIndex, index)
    : html;
}

window.hkdf = function(material, string) {
  var h = etc.crypto.hmac(
    etc.Encoding.decodeFromUTF8(string),
    material
  );

  return {
    key:   h.slice(0, 32),
    nonce: h.slice(32, 56)
  };
}

function update() {
  var rib = {}
  if (q("#ribbon")) {
    rib = q("#ribbon");
  }

  var cc = q(".centralCard");
  if (!cc) return;

  if (window.innerWidth < 500) {
    cc.style = "width: 84vw; margin-top: 20px;";
    rib.style = "display: none";
  } else {
    cc.style = "";
    rib.style = "";
  }
}