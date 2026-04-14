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
    this.setupCodeTheme();
    this.updateProgress();
  }

  setupCodeTheme() {
    const codeBlocks = document.querySelectorAll(".code-block");
    const keywordPattern =
      /\b(import|rule|meta|strings|condition|ascii|wide|nocase|and|or|not|of|true|false|any|all)\b/g;

    codeBlocks.forEach((block) => {
      if (!block.dataset.codeTitle) {
        block.dataset.codeTitle = "Code";
      }

      const codeElement = block.querySelector("code");
      if (!codeElement) {
        return;
      }

      const rawCode = codeElement.textContent || "";
      let html = rawCode
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

      html = html.replace(
        /#.*$/gm,
        (m) => `<span class="code-token-comment">${m}</span>`,
      );
      html = html.replace(
        /"([^"\\]|\\.)*"/g,
        (m) => `<span class="code-token-string">${m}</span>`,
      );
      html = html.replace(
        /\b\d+\b/g,
        (m) => `<span class="code-token-number">${m}</span>`,
      );
      html = html.replace(
        /\b([a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\b/g,
        (_m, p1, p2) => {
          return `<span class="code-token-property">${p1}.${p2}</span>`;
        },
      );
      html = html.replace(
        keywordPattern,
        (m) => `<span class="code-token-keyword">${m}</span>`,
      );

      codeElement.innerHTML = html;
    });
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
    this.slides.forEach((slide, index) => {
      let label = `Slide ${index + 1}`;
      const sectionNum = slide.querySelector(".section-num");
      const heading = slide.querySelector("h2, h1");

      if (slide.classList.contains("title-slide") && index === 0) {
        label = "Title";
      } else if (sectionNum) {
        label = sectionNum.textContent.trim();
      } else if (heading) {
        label = heading.textContent.trim();
      }

      const dot = document.createElement("button");
      dot.className = "nav-dot";
      dot.setAttribute("data-label", label);
      dot.setAttribute("aria-label", `Go to slide ${index + 1}: ${label}`);
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
