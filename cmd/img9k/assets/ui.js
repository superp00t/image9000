window.addEventListener("load", function() {
  update();
});

window.addEventListener("resize", function() {
  update();
});

function update() {
  if (window.innerWidth < 500) {
    document.querySelector(".centralCard").style = "width: 84vw; margin-top: 20px;";
  } else {
    document.querySelector(".centralCard").style = "";
  }
}