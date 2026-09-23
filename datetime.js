/* =========================
   DATE + TIME
========================= */

function updatePassportTime(){

    const now =
    new Date();

    const formatted =
    now.toLocaleString(
        "en-IN",
        {

            weekday:"long",

            day:"2-digit",

            month:"long",

            year:"numeric",

            hour:"2-digit",

            minute:"2-digit",

            second:"2-digit",

            hour12:true

        }
    );

    document.getElementById(
    "passport-datetime"
    ).innerHTML =
    `🕒 ${formatted}`;

}

setInterval(
    updatePassportTime,
    1000
);

updatePassportTime();

/* =========================
   EMERGENCY MODAL
========================= */

function openEmergencyContact(){

    document.getElementById(
    'emergencyModal'
    ).style.display = 'block';

}

function closeEmergencyContact(){

    document.getElementById(
    'emergencyModal'
    ).style.display = 'none';

}