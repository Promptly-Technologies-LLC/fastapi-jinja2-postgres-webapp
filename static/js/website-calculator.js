(() => {
  const calculator = document.querySelector("[data-revenue-calculator]");
  if (!calculator) return;

  const ticketInput = calculator.querySelector("[data-ticket]");
  const missedInput = calculator.querySelector("[data-missed]");
  if (!ticketInput || !missedInput) return;

  const currency = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  });

  const setText = (selector, value) => {
    const element = calculator.querySelector(selector);
    if (element) element.textContent = value;
  };

  const update = () => {
    const ticket = Number(ticketInput.value);
    const missed = Number(missedInput.value);
    const weeklyLoss = ticket * missed;
    const monthlyLoss = weeklyLoss * 4.33;

    setText("[data-ticket-label]", currency.format(ticket));
    setText("[data-missed-label]", String(missed));
    setText("[data-receipt-ticket]", currency.format(ticket));
    setText("[data-receipt-missed]", String(missed));
    setText("[data-weekly-loss]", currency.format(weeklyLoss));
    setText("[data-monthly-loss]", currency.format(monthlyLoss));
  };

  ticketInput.addEventListener("input", update);
  missedInput.addEventListener("input", update);
  update();
})();
