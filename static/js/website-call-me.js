(() => {
  const phoneInput = document.querySelector("#call-me #phone");
  if (phoneInput instanceof HTMLInputElement) {
    let previousDigitCount = 0;

    const onlyDigits = (raw) => {
      let digits = String(raw || "").replace(/\D/g, "");
      if (digits.length === 11 && digits.startsWith("1")) {
        digits = digits.slice(1);
      }
      return digits.slice(0, 10);
    };

    const formatPhone = (raw, { deleting = false } = {}) => {
      const digits = onlyDigits(raw);
      const area = digits.slice(0, 3);
      const mid = digits.slice(3, 6);
      const last = digits.slice(6, 10);
      const n = digits.length;

      if (n === 0) return "";
      if (n < 3) return `(${area}`;
      if (n === 3) return deleting ? `(${area}` : `(${area})`;
      if (n < 6) return `(${area}) ${mid}`;
      if (n === 6) return deleting ? `(${area}) ${mid}` : `(${area}) ${mid} -`;
      return `(${area}) ${mid} - ${last}`;
    };

    const countDigitsBefore = (value, caret) => {
      let count = 0;
      const end = Math.min(caret, value.length);
      for (let i = 0; i < end; i += 1) {
        if (/\d/.test(value[i])) count += 1;
      }
      return count;
    };

    const caretFromDigitCount = (value, digitCount) => {
      if (digitCount <= 0) return 0;
      let seen = 0;
      for (let i = 0; i < value.length; i += 1) {
        if (/\d/.test(value[i])) {
          seen += 1;
          if (seen === digitCount) {
            let pos = i + 1;
            while (pos < value.length && !/\d/.test(value[pos])) pos += 1;
            return pos;
          }
        }
      }
      return value.length;
    };

    const applyFormat = () => {
      const previous = phoneInput.value;
      const selectionStart = phoneInput.selectionStart;
      const caret = selectionStart == null ? previous.length : selectionStart;
      const typingAtEnd = caret >= previous.length;
      const digits = onlyDigits(previous);
      const digitCount = digits.length;
      const deleting = digitCount < previousDigitCount;
      const digitsBefore = countDigitsBefore(previous, caret);
      const next = formatPhone(previous, { deleting });

      previousDigitCount = digitCount;

      if (next !== previous) {
        phoneInput.value = next;
      }

      const nextCaret = typingAtEnd
        ? next.length
        : caretFromDigitCount(next, Math.min(digitsBefore, digitCount));

      try {
        phoneInput.setSelectionRange(nextCaret, nextCaret);
      } catch (_) {
        // Ignore browsers that reject setSelectionRange on tel inputs.
      }
    };

    phoneInput.addEventListener("keydown", (event) => {
      if (event.key !== "Backspace") return;
      if (phoneInput.selectionStart !== phoneInput.selectionEnd) return;

      const caret = phoneInput.selectionStart ?? 0;
      if (caret <= 0) return;

      const charBefore = phoneInput.value[caret - 1];
      if (/\d/.test(charBefore)) return;

      event.preventDefault();
      const digits = onlyDigits(phoneInput.value);
      if (digits.length === 0) {
        phoneInput.value = "";
        previousDigitCount = 0;
        return;
      }

      const trimmed = digits.slice(0, -1);
      previousDigitCount = digits.length;
      phoneInput.value = formatPhone(trimmed, { deleting: true });
      previousDigitCount = trimmed.length;
      const pos = phoneInput.value.length;
      phoneInput.setSelectionRange(pos, pos);
    });

    phoneInput.addEventListener("input", applyFormat);
    phoneInput.addEventListener("blur", () => {
      previousDigitCount = onlyDigits(phoneInput.value).length;
      phoneInput.value = formatPhone(phoneInput.value, { deleting: false });
    });

    if (phoneInput.value) {
      previousDigitCount = onlyDigits(phoneInput.value).length;
      applyFormat();
    }
  }

  const crmSelect = document.querySelector("#call-me #crm");
  const crmOtherField = document.querySelector("#call-me #crm-other-field");
  const crmOtherInput = document.querySelector("#call-me #crm_other");
  if (
    crmSelect instanceof HTMLSelectElement &&
    crmOtherField instanceof HTMLElement &&
    crmOtherInput instanceof HTMLInputElement
  ) {
    const syncCrmOther = () => {
      const showOther = crmSelect.value === "other";
      crmOtherField.hidden = !showOther;
      crmOtherField.classList.toggle("is-hidden", !showOther);
      crmOtherInput.required = showOther;
      if (!showOther) {
        crmOtherInput.value = "";
      }
    };

    crmSelect.addEventListener("change", syncCrmOther);
    syncCrmOther();
  }
})();
