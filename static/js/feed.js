document.addEventListener('DOMContentLoaded', function() {
    const leftElement = document.querySelector('.left');
    if (leftElement) {
        leftElement.addEventListener('click', function() {
            goToTop();
        });
    }
});

function goToTop() {
    window.scrollTo({top: 0, behavior: 'smooth'});
}