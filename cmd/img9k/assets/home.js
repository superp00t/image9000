if (!window.i9k) {
  window.i9k = {};
}

i9k._progress = 0;
i9k.useEncryption = false;

// window.onpopstate = function(event) {
//   if(event && event.state) {
//     location.reload(); 
//   }
// }

NodeList.prototype.on = function(evt, h) {
  for (var i = 0; i < this.length; i++) {
    this[i].addEventListener(evt, h);
  }
}

i9k.dragDefault = "Drag a file over or click me to upload a file!";
i9k.dragHover = "Now let go!";

i9k.setup = function() {
  var s = q("#remove-on-js");
  s.parentNode.removeChild(s);

  // Add encryption checkbox

  // Bind drag-n-drop
  var dragDiv = document.createElement("div");
  dragDiv.setAttribute("class", "dragDiv");
  q(".centralCard").insertBefore(dragDiv, q(".info"));

  var help = document.createElement("p");
  help.setAttribute("class", "help");
  help.innerText = i9k.dragDefault;

  var pf = q("#proxyFile");
  pf.addEventListener("change", function(files) {
    if (pf.files.length === 0) return;

    if (pf.files.length !== 1 && pf.files[1].type !== "video/quicktime") {
      alert("you cannot upload more than one file.");
      return;
    }

    i9k.beginUpload(pf.files[0]);
  });

  q(".dragDiv").addEventListener("click", function() {
    q("#proxyFile").click();
  });

  q(".dragDiv").appendChild(help);  

  document.body.addEventListener("dragover dragenter dragleave drop drag", function(ev) {
    ev.preventDefault();
  });

  var sel = ".dragDiv";
  a(sel).on("dragover", function(e) {
    e.preventDefault();
  });

  a(sel).on("dragenter", function() {
    help.innerText = i9k.dragHover;
  });

  a(sel).on("dragleave", function() {
    help.innerText = i9k.dragDefault
  });

  a(sel).on("drop", function(e) {
    e.preventDefault();
    help.innerText = i9k.dragDefault;
    i9k.dropEvent(e);
  });
}

i9k.dropEvent = function(evt) {
  if (evt.dataTransfer.files.length !== 1) {
    alert("Sorry, but you can only upload one file at a time.");
    return;
  }

  i9k.beginUpload(evt.dataTransfer.files[0]);
}

var u8concat = function(buffer1, buffer2) {
  var tmp = new Uint8Array(buffer1.length + buffer2.length);
  tmp.set(buffer1, 0);
  tmp.set(buffer2, buffer1.length);
  return tmp;
};

i9k.beginUpload = function(file) {
  if (file.size > (i9k.cfg.maxFileSize-6000)) {
    alert("That file is too large, sorry.");
    return;
  }

  q(".dragDiv").style = "display: none;";
  const progBar = `<div class="cssProgress">
    <div class="progress3">
      <div class="cssProgress-bar cssProgress-active-right" data-percent="0" style="width: 0%;"><span class="cssProgress-label">0%</span> </div>
    </div>
   </div>`

  q(".centralCard").insertBefore(
    parseHtml(progBar),
    q(".info")
  );

  i9k.postFile(file);
}

i9k.postFile = function(file) {
  var fData = new FormData();
  fData.append("file", file);
  
  var x = new XMLHttpRequest();
  x.onreadystatechange = function() {
    if (x.readyState === 4) {
      if (x.status < 400) {
        window.location.href = x.responseURL;
      } else {
        alert(x.statusText + ": " + x.responseText);
        window.location.reload();
      }
    }
  }

  x.upload.onprogress = function(ev) {
    var pct = Math.floor((ev.loaded / ev.total) * 100);
    i9k.setProgressBar(pct);
  }

  x.open("POST", "/upload?x=1");
  x.send(fData);
}

i9k.setProgressBar = function(progress) {
  // If   progress = 50
  // and  i9k.progress = 60
  if (progress < i9k.progress) {
    return;
  }

  i9k.progress = progress;
  var p = q(".cssProgress-bar");
  p.setAttribute("data-percent", progress);
  p.style = "width: " + progress + "%;";
  q(".cssProgress-label").innerText = progress + "%";
}

window.addEventListener("load", i9k.setup);

