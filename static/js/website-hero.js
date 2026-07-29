(() => {
  const root = document.querySelector("[data-hero-showcase]");
  if (!root) return;

  const cards = Array.from(root.querySelectorAll(".website-hero__card"));
  const genreStrip = root.querySelector(".website-hero__genres");
  if (!cards.length || !genreStrip) return;

  const originals = Array.from(genreStrip.querySelectorAll(".website-hero__genre"));
  if (!originals.length) return;

  const count = originals.length;

  // Three copies: work in the middle set so both sides always have neighbors.
  for (let copy = 0; copy < 2; copy += 1) {
    originals.forEach((genre) => {
      const clone = genre.cloneNode(true);
      clone.setAttribute("aria-hidden", "true");
      clone.tabIndex = -1;
      genreStrip.appendChild(clone);
    });
  }

  const genres = Array.from(genreStrip.querySelectorAll(".website-hero__genre"));

  let index = 0;
  // Start on the middle copy so neighbors exist on both sides.
  let visualIndex = count;
  let timer = null;
  let transitioning = false;
  const INTERVAL_MS = 2600;

  function loopWidth() {
    return genres[count].offsetLeft - genres[0].offsetLeft;
  }

  function centerOn(buttonIndex, behavior = "smooth") {
    const button = genres[buttonIndex];
    if (!button) return;

    const stripRect = genreStrip.getBoundingClientRect();
    const genreRect = button.getBoundingClientRect();
    const target =
      genreStrip.scrollLeft +
      (genreRect.left - stripRect.left) -
      (stripRect.width - genreRect.width) / 2;

    genreStrip.scrollTo({ left: target, behavior });
  }

  function syncActiveClasses() {
    cards.forEach((card, i) => {
      const active = i === index;
      card.classList.toggle("is-active", active);
      card.setAttribute("aria-hidden", active ? "false" : "true");
    });

    genres.forEach((genre) => {
      const active = Number(genre.dataset.slideIndex) === index;
      genre.classList.toggle("is-active", active);
      if (genre.getAttribute("aria-hidden") !== "true") {
        genre.setAttribute("aria-selected", active ? "true" : "false");
      }
    });
  }

  /**
   * Instantly shift scroll by whole loops so visualIndex stays in the middle
   * copy [count, 2*count). Content looks identical; no animation.
   */
  function snapToMiddleCopy() {
    const width = loopWidth();
    if (!width) return;

    while (visualIndex >= 2 * count) {
      genreStrip.scrollLeft -= width;
      visualIndex -= count;
    }
    while (visualIndex < count) {
      genreStrip.scrollLeft += width;
      visualIndex += count;
    }
  }

  /**
   * Before a forward step, if the next pill would be past the middle copy,
   * jump back one loop first so we always smooth-scroll onto a real node.
   */
  function prepareForwardStep() {
    if (visualIndex < 2 * count - 1) return;
    const width = loopWidth();
    if (!width) return;
    genreStrip.scrollLeft -= width;
    visualIndex -= count;
  }

  function setActive(nextIndex, targetVisual, behavior = "smooth") {
    index = ((nextIndex % count) + count) % count;
    visualIndex = targetVisual;
    syncActiveClasses();
    centerOn(visualIndex, behavior);
  }

  function next() {
    if (transitioning) return;
    transitioning = true;

    prepareForwardStep();
    setActive(index + 1, visualIndex + 1, "smooth");

    window.setTimeout(() => {
      snapToMiddleCopy();
      transitioning = false;
    }, 500);
  }

  function start() {
    stop();
    timer = window.setInterval(next, INTERVAL_MS);
  }

  function stop() {
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  genreStrip.addEventListener("click", (event) => {
    const button = event.target.closest(".website-hero__genre");
    if (!button || !genreStrip.contains(button)) return;

    const nextIndex = Number(button.dataset.slideIndex || 0);
    let targetVisual = genres.indexOf(button);

    // Prefer the forward instance when the strip is moving ahead.
    if (targetVisual <= visualIndex) {
      const forwardTwin = targetVisual + count;
      if (forwardTwin < genres.length && forwardTwin > visualIndex) {
        targetVisual = forwardTwin;
      }
    }

    // Keep selection in/near the middle copy when possible.
    if (targetVisual < count) {
      targetVisual += count;
    } else if (targetVisual >= 2 * count) {
      targetVisual -= count;
      genreStrip.scrollLeft -= loopWidth();
    }

    transitioning = false;
    setActive(nextIndex, targetVisual);
    start();
  });

  root.addEventListener("mouseenter", stop);
  root.addEventListener("mouseleave", start);

  syncActiveClasses();
  centerOn(visualIndex, "auto");
  start();
})();
