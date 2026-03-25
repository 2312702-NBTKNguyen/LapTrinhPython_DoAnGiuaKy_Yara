class SlidePresentation {
  constructor() {
    this.slides = document.querySelectorAll(".slide");
    this.currentSlide = 0;
    this.totalSlides = this.slides.length;
    this.progressBar = document.getElementById("progressBar");
    this.slideNumberEl = document.getElementById("slideNumber");
    this.navDotsContainer = document.getElementById("navDots");

    this.setupIntersectionObserver();
    this.setupKeyboardNav();
    this.setupNavDots();
    this.updateProgress();
  }

  setupIntersectionObserver() {
    const options = {
      root: null,
      rootMargin: "0px",
      threshold: 0.5,
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
          const index = Array.from(this.slides).indexOf(entry.target);
          if (index !== -1) {
            this.currentSlide = index;
            this.updateProgress();
            this.updateNavDots();
            this.updateSlideNumber();
          }
        }
      });
    }, options);

    this.slides.forEach((slide) => observer.observe(slide));
  }

  setupKeyboardNav() {
    document.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowDown" || e.key === " ") {
        e.preventDefault();
        this.nextSlide();
      } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        e.preventDefault();
        this.prevSlide();
      } else if (e.key === "Home") {
        e.preventDefault();
        this.goToSlide(0);
      } else if (e.key === "End") {
        e.preventDefault();
        this.goToSlide(this.totalSlides - 1);
      }
    });
  }

  setupNavDots() {
    const labels = [
      "Title",
      "Mục lục",
      "Tổng quan",
      "Cấu trúc",
      "Thành phần",
      "3 lớp phát hiện",
      "Luồng quét",
      "YARA Rules",
      "Ví dụ Rule",
      "Archive",
      "Database",
      "Báo cáo",
      "Cài đặt",
      "CLI",
      "Exceptions",
      "Dependencies",
      "Tổng kết",
      "Cảm ơn",
    ];

    this.slides.forEach((_, index) => {
      const dot = document.createElement("button");
      dot.className = "nav-dot";
      dot.setAttribute("data-label", labels[index] || `Slide ${index + 1}`);
      dot.setAttribute(
        "aria-label",
        `Go to slide ${index + 1}: ${labels[index]}`,
      );
      dot.addEventListener("click", () => this.goToSlide(index));
      this.navDotsContainer.appendChild(dot);
    });

    this.updateNavDots();
  }

  goToSlide(index) {
    if (index >= 0 && index < this.totalSlides) {
      this.slides[index].scrollIntoView({ behavior: "smooth" });
    }
  }

  nextSlide() {
    if (this.currentSlide < this.totalSlides - 1) {
      this.goToSlide(this.currentSlide + 1);
    }
  }

  prevSlide() {
    if (this.currentSlide > 0) {
      this.goToSlide(this.currentSlide - 1);
    }
  }

  updateProgress() {
    const progress = ((this.currentSlide + 1) / this.totalSlides) * 100;
    this.progressBar.style.width = `${progress}%`;
  }

  updateNavDots() {
    const dots = this.navDotsContainer.querySelectorAll(".nav-dot");
    dots.forEach((dot, index) => {
      dot.classList.toggle("active", index === this.currentSlide);
    });
  }

  updateSlideNumber() {
    const num = String(this.currentSlide + 1).padStart(2, "0");
    const total = String(this.totalSlides).padStart(2, "0");
    this.slideNumberEl.textContent = `${num} / ${total}`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new SlidePresentation();
});
