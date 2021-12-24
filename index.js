function clearTextBox() {
  url.value = "";
  document.getElementById("status").innerText = "";
  document.getElementById("status").style.color = "black";
  document.getElementsByClassName("sURL")[0].setAttribute("href", "");
  document.getElementsByClassName("sURL")[0].innerHTML = "";
  document.getElementsByClassName("safety")[0].innerHTML = "URL Safe:";
}




function copyURL() {
  window.copied = document.getElementById("copy");
  copied.select();
  // copied.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(shortUrl);
}




function enter(event) {
  if (event.key === "Enter" || event.keyCode === 13) {
    event.preventDefault();
    // getp();
    document.getElementById("scan").click();
  }
}





function getp() {
  window.urll = url.value;
  if (urll === "" || urll[0] === " ") {
    // alert("Enter a valid url");
    document.getElementById("status").innerText = "Enter a Valid URL";
    document.getElementById("status").style.color = "red";
    urll.value = "";
    return;
  }

  // }
  // function getz(){
  var data1;
  var ID;
  getId();

  function getId() {
    const options = {
      method: "POST",
      headers: {
        Accept: "application/json",
        "x-apikey":
          "6d96efe421861509b0b7ec99c33a98a7671b0b0d2c3af7d4f31eb31256796502",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ url: urll }),
    };

    fetch("https://www.virustotal.com/api/v3/urls", options)
      .then((response) => response.json())
      .then((response) => {
        if (response) {
          // url.value = null;
          data1 = response.data;
          if (data1 == undefined) {
            document.getElementById("status").innerText = "Error!!!";
            document.getElementById("myH2").style.color = "red";
            // return;
          }
          ID = data1.id;
          getData(ID);
          ID = 0;
        }
      })
      .catch((err) => console.error(err));

    // }

    function getData(id) {
      var analysis;

      const options2 = {
        method: "GET",
        headers: {
          Accept: "application/json",
          "x-apikey":
            "6d96efe421861509b0b7ec99c33a98a7671b0b0d2c3af7d4f31eb31256796502",
        },
      };

      fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, options2)
        .then((response1) => response1.json())
        .then((response1) => {
          analysis = response1.data;
          printData(analysis);
          if (analysis.attributes.status == "queued") {
            document.getElementById("status").innerText = "Processing...";
            getId();
            return;
          }
          console.log(analysis);
        })
        .catch((err) => console.error(err));
    }

    function printData(urlData) {
      harmless = urlData.attributes.stats.harmless;
      malicious = urlData.attributes.stats.malicious;

      if ((harmless !== 0 || malicious !== 0) && harmless > malicious) {
        document.getElementsByClassName("safety")[0].innerHTML = "URL Safe: ✅";
        getShortUrl();
      } else if ((harmless !== 0 || malicious !== 0) && harmless < malicious) {
        document.getElementsByClassName("safety")[0].innerHTML =
          "URL Safe:  ❌";
        return;
      }
      // else{
      //   document.getElementsByTagName("h2")[0].innerHTML = 'SCANNING......';
      // }
    }

    function getShortUrl() {
      fetch("https://api-ssl.bitly.com/v4/shorten", {
        method: "POST",
        headers: {
          Authorization: "Bearer c46d9bc50d7d73df3acce33edbe612fd6f305f31",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ long_url: urll, domain: "bit.ly" }),
      }).then((response) =>
        response.json().then((data) => {
          window.shortUrl = data.id;
          document.getElementById("status").innerText = "URL shortened";
          document.getElementById("status").style.color = "green";
          document
            .getElementsByClassName("sURL")[0]
            .setAttribute("href", "http://" + shortUrl);
          document.getElementsByClassName("sURL")[0].innerHTML = shortUrl;
        })
      );
    }

  }
}
