// Access webcam
navigator.mediaDevices.getUserMedia({ video: true })
    .then(stream => {
        document.getElementById('video').srcObject = stream;
    })
    .catch(err => console.error("Error accessing webcam: ", err));
