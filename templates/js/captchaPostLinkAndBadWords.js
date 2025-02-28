function findLink(checkValue) {
    regexp = /[-a-zA-Z0-9@:%_\+.~#?&\/=]{2,256}\.[a-z]{2,4}\b(\/[-a-zA-Z0-9@:%_\+.~#?&\/=]*)?/gi;
    
    if (regexp.test(checkValue)) {
        return checkValue.replace(regexp, "(ссылка удалена)");
    } 
    
    return checkValue;
}

function onClickPost() {
    const inputElement = document.querySelector(".revText");
    const inputValue = inputElement.value;
    
    let testStr = makeStr(makeCount());
    const ansCapthca = prompt("Подтвердите, что вы человек.\nВведите строку: " + testStr, "");
    
    if(ansCapthca == null) {
        alert("Чтобы отправить отзыв нужно ввести каптчу! Попробуйте снова");
    } else {
        if(ansCapthca == testStr) {
            alert("Отзыв отправлен!");
    
            let newDiv = document.createElement("div");
            newDiv.append(findLink(inputValue));
            
            document.querySelector(".reviews_area").append(newDiv);
            
            inputElement.value = "";
        } else {
            alert("Вы неправильно ввели каптчу! Попробуйте снова");
        }
    }
}

