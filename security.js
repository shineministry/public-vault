/* =========================
   SCREENSHOT PROTECTION SITE
========================= */

function triggerScreenProtection(){

    const shield =
    document.createElement('div');

    shield.id =
    "screen-protection-layer";

    shield.style.position =
    "fixed";

    shield.style.inset =
    "0";

    shield.style.background =
    "white";

    shield.style.zIndex =
    "999999";

    shield.style.pointerEvents =
    "none";

    document.body.appendChild(
    shield
    );

    setTimeout(()=>{

        shield.remove();

    },1200);

}

// Detect PrintScreen key

document.addEventListener(
'keyup',
(e)=>{

    if(e.key === 'PrintScreen'){

        triggerScreenProtection();

        sendSecurityAlert(
        "Screenshot attempt detected"
        );

    }

});

// Blur when tab hidden

document.addEventListener(
'visibilitychange',
()=>{

    if(document.hidden){

        triggerScreenProtection();

    }

});

   document
.addEventListener(
'click',
function(e){

if(
e.target.id !==
'generateQRBtn'
)
return;

const shareLink =
document
.getElementById(
'share-link-text'
)
.textContent
.trim();

if(!shareLink){

toastNotify('Generate link first.', 'warning');

return;
}

document
.getElementById(
'qr-box'
)
.style.display =
'block';

const canvas =
document
.getElementById(
'qrCanvas'
);

canvas
.getContext('2d')
.clearRect(
0,
0,
canvas.width,
canvas.height
);

QRCode.toCanvas(

canvas,

shareLink,

{
    width:220
},

function(error){

if(error){

console.error(
error
);

toastNotify('QR generation failed.', 'error');
}
});

});

   function activateShareQR() {
    // 1. Fetch the text value of the generated secure link 
    const shareLinkText = document.getElementById('share-link-text').textContent.trim();
    
    if (!shareLinkText || shareLinkText === "") {
        toastNotify('Please generate a secure link first before rendering its QR Code.', 'warning');
        return;
    }
    
    const canvasTarget = document.getElementById('qrCanvas');
    const qrBoxContainer = document.getElementById('qr-box');
    
    // 2. Execute the render logic belonging to your standard jsdelivr build
    QRCode.toCanvas(canvasTarget, shareLinkText, {
        width: 230,
        margin: 1,
        color: {
            dark: "#0f172a",
            light: "#ffffff"
        }
    }, function (error) {
        if (error) {
            console.error('QR Generation failed:', error);
            toastNotify('Could not construct QR code reference.', 'error');
            return;
        }
        // 3. Make the hidden block visible once the matrix is cleanly generated
        qrBoxContainer.style.display = 'block';
    });
}
