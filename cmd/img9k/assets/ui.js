window.addEventListener("load", function() {
  update();
});

window.addEventListener("resize", function() {
  update();
});

if (!q) {
  window.q = (s) => document.querySelector(s);
}

function update() {
  if (window.innerWidth < 500) {
    q(".centralCard").style = "width: 84vw; margin-top: 20px;";
    q("#ribbon").style = "display: none";
  } else {
    q(".centralCard").style = "";
    q("#ribbon").style = "";
  }
}