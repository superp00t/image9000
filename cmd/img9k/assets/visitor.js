window.addEventListener("load", () => {
  var hash = window.location.hash.slice(1);

  // Encryption has been enabled
  if (img9k.content.endsWith(".i9k")) {
    fetch("/i/" + img9k.content)
    .then((e) => e.arrayBuffer())
    .then((data) => {
      var material = etc.Encoding.decodeFromURL(hash);

      var h = hkdf(material, window.location.hostname);
  
      var key = h.key;
      var nonce = h.nonce;
  
      var decrypted = etc.crypto.nacl.secretbox.open(new Uint8Array(data), nonce, key);
      if (!decrypted) {
        window.location.href = "/";
        return;
      }

      decrypted = new etc.Buffer(decrypted);
      var mtype = decrypted.readString().split(";")
      var txtType = ""
      if (mtype[1]) {
        txtType = ";" + mtype[1];
      }
      var mimeType = mtype[0];

      decrypted.readLimitedBytes();

      var dataBuffer = decrypted.remainingBytes();

      var displayedType = mimeType;
      var type = "dl";
      var ext = "bin"

      var process = {
        "application/zip": [false, "dl", "zip"],
        "application/gzip": [false, "dl", "gz"],
        "image/svg+xml": [true, "img",  "svg"],
        "image/png":     [false, "img",  "png"],
        "image/gif":     [false, "img",  "gif"],
        "video/mp4":     [false, "video","mp4"],
        "video/webm":    [false, "video", "webm"],
        "video/x-matroska": [false, "video", "mkv"],
        "audio/ogg":        [false, "audio", "ogg"],
        "audio/mpeg":        [false, "audio", "mp3"],
        "audio/mp3":        [false, "audio", "mp3"],
        "audio/wav":        [false, "audio", "wav"],
        "application/xml":  [true, "dl", "xml"],
        "text/html":        [true, "dl", "html"]
      }

      var ext = "dat";

      if (!process[mimeType]) {
        mimeType = "application/octet-stream";
      } else {
        mimeType += txtType;
        ext = process[mimeType][2];
        type = process[mimeType][1];
        if (process[mimeType][0]) {
          var str = etc.Encoding.encodeToUTF8(dataBuffer);
          str = DOMPurify.sanitize(str);
          dataBuffer = etc.Encoding.decodeFromUTF8(str);
        }
      }

      q(".logo").innerText = ext.toUpperCase() + " File";
      q(".centralCard").innerHTML += `<p id="mime"></p><div class="content"></div>`;

      var _blob = new Blob([dataBuffer], { type: mimeType });
      
      var blob = window.URL.createObjectURL(_blob);

      var txt = "";

      switch (type) {
        case "video":
        txt = `<video controls src="${blob}"></video>`;
        break;

        case "audio":
        txt = `<audio controls src="${blob}"></audio>`;
        break;

        case "img":
        txt = `<img src="${blob}"></img>`;
        break;

        default:
        break;
      }

      q("#downloadURL").setAttribute("href", blob);
      q("#downloadURL").setAttribute("download", etc.Encoding.encodeToURL(etc.crypto.nacl.randomBytes(18)) + "." + ext);
      q("#mime").innerHTML = "MIME Type: " + escapeHtml(displayedType);
      q(".content").innerHTML = txt;
    });
  }
});

