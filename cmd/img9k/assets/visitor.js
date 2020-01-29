const plyrConfig = {
  disableContextMenu: false
};


function darkenBackground() {
  document.body.style = "background: #111; position: relative; height: 100%;";
}

function mp3Player(url) {
  darkenBackground();
  document.body.innerHTML =
  `<div id="player_container">
    <audio id="player">
      <source src="${url}" type="${img9k.mime}"/>
    </audio>
  </div>`;
  new Plyr('#player', plyrConfig);
}

function mp4Player(url) {
  darkenBackground();
  document.body.innerHTML =
  `<div id="player_container">
    <video id="player" crossorigin playsinline controls loop>
      <source src="${url}" type="${img9k.mime}"/>
    </video>
  </div>`;
  new Plyr('#player', plyrConfig);
}

var audioFormats = ["ogg", "flac", "mp3", "wav"];
var videoFormats = ["mp4", "webm", "mkv"];

window.addEventListener("load", () => {
  var ext = img9k.content.split(".")[1];

  var hash = window.location.hash.slice(1);

  if (audioFormats.includes(ext)) {
    mp3Player("/i/" + img9k.content);
    return;
  }

  if (videoFormats.includes(ext)) {
    mp4Player("/i/" + img9k.content);
    return;
  }
});

