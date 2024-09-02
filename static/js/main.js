

document.addEventListener("DOMContentLoaded", () => {
    const yearSpan = document.getElementById("year");

    // Set current year
    const currentYear = new Date().getFullYear();
    if (yearSpan) {
        yearSpan.textContent = currentYear;
    }

});