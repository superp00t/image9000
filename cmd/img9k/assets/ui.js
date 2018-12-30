window.addEventListener("load", function() {
  update();
});

window.addEventListener("resize", function() {
  update();
});

function update() {
  if (window.innerWidth < 500) {
    q(".centralCard").style = "width: 84vw; margin-top: 60px;";
  } else {
    q(".centralCard").style = "";
  }
}