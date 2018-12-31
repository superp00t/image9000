if (!window.i9k) {
  window.i9k = {};
}

window.onpopstate = function(event) {
  if(event && event.state) {
    location.reload(); 
  }
}

var q = (s) => document.querySelector(s);
var a = (s) => document.querySelectorAll(s);

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

  // Bind drag-n-drop
  var dragDiv = document.createElement("div");
  dragDiv.setAttribute("class", "dragDiv");
  q(".centralCard").insertBefore(dragDiv, q(".info"));

  var help = document.createElement("p");
  help.setAttribute("class", "help");
  help.innerText = i9k.dragDefault;

  var pf = q("#proxyFile");
  pf.addEventListener("change", function(files) {
    if (pf.files.length !== 1) {
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

i9k.beginUpload = function(file) {
  q(".dragDiv").style = "display: none;";
  const progBar = `<div class="cssProgress">
    <div class="progress3">
      <div class="cssProgress-bar cssProgress-active-right" data-percent="0" style="width: 0%;"><span class="cssProgress-label">0%</span> </div>
    </div>
   </div>`

  q(".centralCard").insertBefore(
    new DOMParser().parseFromString(progBar, "text/html").body.childNodes[0],
    q(".info")
  );

  var fData = new FormData();
  fData.append("file", file);
  
  var x = new XMLHttpRequest();
  x.onreadystatechange = function() {
    if (x.readyState === 4) {
      window.location.href = x.responseURL;
    }
  }

  x.upload.onprogress = function(ev) {
    i9k.setProgressBar(Math.floor(ev.loaded / ev.total) * 100);
  }

  x.open("POST", "/upload");
  x.send(fData);
}

i9k.setProgressBar = function(progress) {
  var p = q(".cssProgress-bar");
  p.setAttribute("data-percent", progress);
  p.style = "width: " + progress + "%;";
  q(".cssProgress-label").innerText = progress + "%";
}

window.addEventListener("load", i9k.setup);

