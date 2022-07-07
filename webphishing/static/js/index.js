const btnNav = document.getElementById("btn-nav");
const mobileNavContainer = document.getElementById("mobile-nav-container");

btnNav.addEventListener("click", (e) => {
	console.log(e);
	if (btnNav.classList.contains("open")) {
		mobileNavContainer.style.transform = " translateX(0%) translateZ(0px)";
		btnNav.classList.remove("open");
		btnNav.classList.add("close");
	} else {
		mobileNavContainer.style.transform = " translateX(150%) translateZ(0px)";
		btnNav.classList.remove("close");
		btnNav.classList.add("open");
	}
});
