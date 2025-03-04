document.addEventListener("DOMContentLoaded", function () {
    const footer = document.querySelector("footer");

    // Функция для проверки достижения конца страницы
    function checkScroll() {
        if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 10) {
            // Если достигнут конец страницы, показываем footer
            footer.style.opacity = "1";
            footer.style.transform = "translateY(0)";
        } else {
            // Иначе скрываем footer
            footer.style.opacity = "0";
            footer.style.transform = "translateY(50px)";
        }
    }

    // Отслеживаем событие прокрутки
    window.addEventListener("scroll", checkScroll);

    // Вызываем функцию один раз при загрузке страницы
    checkScroll();
});