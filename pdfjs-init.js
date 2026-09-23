// pdfjs-init.js — sets the worker path once pdfjsLib is available
// Uses a local copy of the worker so it works offline too.
// Download pdf.worker.min.js from:
// https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js
// and place it in your site root.

(function () {
    function initWorker() {
        if (window.pdfjsLib) {
            window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'pdf.worker.min.js';
        }
    }
    // If pdfjsLib already loaded, init immediately; otherwise wait for window load
    if (window.pdfjsLib) {
        initWorker();
    } else {
        window.addEventListener('load', initWorker);
    }
})();
