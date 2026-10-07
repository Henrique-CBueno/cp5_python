"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
const e = escapeHtml;
const number = (value) => Number(value || 0).toLocaleString("pt-BR");
const date = (value) =>
  value
    ? new Date(value.length === 10 ? value + "T12:00:00" : value).toLocaleDateString("pt-BR")
    : "Não informado";
const timestamp = (value) =>
  value
    ? new Date(value).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" })
    : "Não informado";
const labels = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Média",
  LOW: "Baixa",
  NONE: "Nenhuma",
  UNASSESSED: "Sem avaliação",
  UNKNOWN: "Não informada",
  pending: "Pendente",
  sending: "Enviando",
  sent: "Enviado",
  failed: "Falhou",
  cancelled: "Cancelado",
  queued: "Na fila",
  running: "Executando",
  completed: "Concluída",
};
const severityColors = {
  CRITICAL: "#a8372e",
  HIGH: "#b56b32",
  MEDIUM: "#ad8b36",
  LOW: "#3f8268",
  NONE: "#667788",
  UNASSESSED: "#8b99ae",
};
let session = { user: null, csrf: "" };

function notify(message, error = false) {
  $("#notice-text").textContent = message;
  $("#notice").hidden = false;
  $("#notice").classList.toggle("error", error);
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...options.headers };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = session.csrf;
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  if (response.status === 204) return null;
  const data = await response.json();
  if (response.status === 401 && ["admin", "alerts"].includes(document.body.dataset.view)) {
    location.assign("/entrar?next=" + encodeURIComponent(location.pathname + location.search));
  }
  if (!response.ok) {
    const message =
      typeof data.detail === "string"
        ? data.detail
        : "Verifique os campos informados e tente novamente.";
    throw new Error(message);
  }
  return data;
}

async function action(button, operation) {
  button.disabled = true;
  try {
    await operation();
  } catch (error) {
    notify(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function badge(value) {
  const normalized = Object.hasOwn(labels, value) ? value : "UNASSESSED";
  return `<span class="badge ${e(normalized.toLowerCase())}">${e(labels[normalized])}</span>`;
}

function assessmentBadge(record) {
  const primary = record.nvd?.primary;
  return (
    badge(primary?.severity || "UNASSESSED") +
    (primary ? `<span class="score">${e(primary.score)}</span>` : "")
  );
}

function watchLink(record) {
  const next = `/alertas?watch=${encodeURIComponent(record.product_key)}`;
  return session.user ? next : `/entrar?next=${encodeURIComponent(next)}`;
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function metrics(stats, target = "#metrics") {
  $(target).innerHTML = [
    [number(stats.total), "Vulnerabilidades na base"],
    [number(stats.vendors_count), "Fornecedores distintos"],
    [`${number(stats.ransomware_percent)}%`, "Ransomware conhecido"],
    [`${number(stats.assessed_percent)}%`, "Com avaliação CVSS"],
  ]
    .map(
      ([value, label]) =>
        `<div class="metric"><strong>${e(value)}</strong><span>${e(label)}</span></div>`,
    )
    .join("");
}

const charts = new Map();
function chart(id, values, type = "bar", horizontal = true, severity = false) {
  const canvas = $(`#${id}-chart`);
  if (!canvas) return;
  charts.get(id)?.destroy();
  const data = values.map((v) => ({ ...v, label: labels[v.label] || v.label }));
  const colors = severity
    ? values.map((v) => severityColors[v.label] || "#8b99ae")
    : values.map((_, i) => ["#315db5", "#587fc2", "#7b9ad0", "#9db4df"][i % 4]);
  if (typeof Chart !== "undefined") {
    Chart.defaults.font.family = "Public Sans, sans-serif";
    Chart.defaults.color = "#5c697a";
    Chart.defaults.font.size = 11;
    charts.set(
      id,
      new Chart(canvas, {
        type,
        data: {
          labels: data.map((v) => v.label),
          datasets: [
            {
              label: "Vulnerabilidades",
              data: data.map((v) => v.count),
              backgroundColor: colors,
              borderColor: "#315db5",
              borderWidth: type === "line" ? 2 : 0,
              borderRadius: 3,
              pointRadius: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          indexAxis: horizontal ? "y" : "x",
          plugins: { legend: { display: false } },
          scales: {
            x: {
              grid: { display: !horizontal, color: "#edf0f5" },
              ticks: { precision: 0, font: { size: 11 } },
            },
            y: {
              grid: { display: horizontal, color: "#edf0f5" },
              ticks: { precision: 0, font: { size: 11 } },
            },
          },
        },
      }),
    );
  }
  $(`#${id}-data`).innerHTML = data.length
    ? `<table><thead><tr><th>Grupo</th><th>Registros</th></tr></thead><tbody>${data.map((v) => `<tr><td>${e(v.label)}</td><td>${number(v.count)}</td></tr>`).join("")}</tbody></table>`
    : '<p class="field-hint">Sem dados para o filtro selecionado.</p>';
}

function renderCharts(stats) {
  chart("vendors", stats.vendors);
  chart("severity", stats.severity, "bar", true, true);
  chart("months", stats.months, "line", false);
  chart("cwes", stats.cwes);
  chart("ransomware", stats.ransomware_vendors);
  if ($("#insights"))
    $("#insights").innerHTML = [
      [
        "Concentração por fornecedor",
        `${number(stats.top5_percent)}% dos registros estão nos cinco fornecedores mais presentes no conjunto filtrado.`,
      ],
      [
        "Inclusões recentes",
        `${number(stats.recent_count)} vulnerabilidades foram incluídas no KEV nos últimos 30 dias.`,
      ],
      [
        "Críticas com ransomware conhecido",
        `${number(stats.critical_ransomware)} registros combinam severidade crítica na avaliação principal e uso conhecido em ransomware.`,
      ],
    ]
      .map(
        ([title, text]) =>
          `<article class="insight"><h2>${e(title)}</h2><p>${e(text)}</p></article>`,
      )
      .join("");
}

async function initFilters(refresh) {
  const form = $("#filters");
  const products = await api("/api/products");
  [...new Set(products.map((p) => p.vendor))]
    .sort()
    .forEach((v) => $("#vendor").add(new Option(v, v)));
  products.forEach((p) => $("#product_key").add(new Option(`${p.vendor} / ${p.product}`, p.key)));
  const params = new URLSearchParams(location.search);
  for (const control of [...form.elements])
    if (control.name && params.has(control.name)) control.value = params.get(control.name);
  const query = () => {
    const data = new URLSearchParams();
    for (const control of [...form.elements])
      if (control.name && control.value) data.set(control.name, control.value);
    return data;
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    history.replaceState(null, "", location.pathname + (query().size ? "?" + query() : ""));
    refresh(query(), true);
  });
  form.addEventListener("reset", () => {
    setTimeout(() => {
      history.replaceState(null, "", location.pathname);
      refresh(query(), true);
    }, 0);
  });
  return query;
}

function inspection(record) {
  const primary = record.nvd?.primary;
  const container = $("#inspection");
  container.innerHTML = `<div class="inspection-meta"><span class="muted">Evidência selecionada</span>${assessmentBadge(record)}</div><h2>${e(record.cve_id)}</h2><p class="product-title">${e(record.vendor)} / ${e(record.product)}</p><h3>${e(record.title)}</h3><p>${e(record.description)}</p><dl><div><dt>Incluída no KEV</dt><dd>${date(record.date_added)}</dd></div><div><dt>Prazo CISA</dt><dd>${date(record.due_date)}</dd></div><div><dt>Ransomware</dt><dd>${record.ransomware === "Known" ? "Uso conhecido" : "Não confirmado"}</dd></div><div><dt>Avaliação principal</dt><dd>${primary ? `CVSS ${e(primary.version)}` : "Não disponível"}</dd></div></dl><h3>Ação recomendada</h3><p>${e(record.action)}</p><div class="inspection-actions"><a class="button primary" href="/vulnerabilidades/${encodeURIComponent(record.cve_id)}">Investigar em detalhes</a><a class="button" href="${e(watchLink(record))}">Acompanhar este produto</a></div><p class="field-hint" style="margin-top:16px">O prazo exibido é o informado pela CISA; não é uma obrigação universal.</p>`;
  $(".inspection-meta .muted", container).remove();
  container.classList.remove("updated");
  requestAnimationFrame(() => container.classList.add("updated"));
}

async function workbench() {
  let page = 1,
    total = 0,
    selected = null,
    requestNumber = 0,
    inspectionNumber = 0;
  const query = await initFilters(refresh);
  async function select(cve) {
    const requestId = ++inspectionNumber;
    try {
      const record = await api(`/api/vulnerabilities/${encodeURIComponent(cve)}`);
      if (requestId !== inspectionNumber) return;
      selected = cve;
      $$("#results tr[data-cve]").forEach((row) =>
        row.classList.toggle("selected", row.dataset.cve === cve),
      );
      $$("#results [data-inspect]").forEach((button) =>
        button.setAttribute("aria-pressed", String(button.dataset.inspect === cve)),
      );
      inspection(record);
    } catch (error) {
      notify(error.message, true);
    }
  }
  async function refresh(params = query(), reset = false) {
    if (reset) page = 1;
    const requestId = ++requestNumber;
    $(".results-panel").setAttribute("aria-busy", "true");
    try {
      const listParams = new URLSearchParams(params);
      listParams.set("page", page);
      listParams.set("page_size", 10);
      const [result, stats] = await Promise.all([
        api("/api/vulnerabilities?" + listParams),
        api("/api/statistics?" + params),
      ]);
      if (requestId !== requestNumber) return;
      total = result.total;
      metrics(stats);
      renderCharts(stats);
      $("#result-count").textContent = `${number(total)} registros`;
      $("#results").innerHTML = result.items.length
        ? result.items
            .map(
              (r) =>
                `<tr data-cve="${e(r.cve_id)}" class="${r.cve_id === selected ? "selected" : ""}"><td><button type="button" class="record-link" data-inspect="${e(r.cve_id)}" aria-label="Inspecionar ${e(r.cve_id)}" aria-pressed="${r.cve_id === selected}">${e(r.cve_id)}</button><span class="product-line" title="${e(r.vendor + " / " + r.product)}">${e(r.vendor)} / ${e(r.product)}</span></td><td>${assessmentBadge(r)}</td><td>${date(r.date_added)}</td><td><a class="inspect-button" href="/vulnerabilidades/${encodeURIComponent(r.cve_id)}" aria-label="Abrir detalhes de ${e(r.cve_id)}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="m9 5 7 7-7 7"/></svg></a></td></tr>`,
            )
            .join("")
        : '<tr><td colspan="4" class="empty"><h2>Nenhuma vulnerabilidade encontrada</h2><p>Ajuste a busca ou limpe os filtros. Se a base estiver vazia, execute a coleta pelo admin.</p></td></tr>';
      $("#page-label").textContent = total
        ? `Página ${page} de ${Math.ceil(total / 10)}`
        : "Sem resultados";
      $("#prev-page").disabled = page <= 1;
      $("#next-page").disabled = page * 10 >= total;
      if (result.items.length)
        await select(
          result.items.find((r) => r.cve_id === selected)?.cve_id || result.items[0].cve_id,
        );
      else {
        ++inspectionNumber;
        selected = null;
        $("#inspection").innerHTML =
          '<div class="empty"><h2>Sem evidência selecionada</h2><p>Os resultados aparecerão aqui após ajustar os filtros.</p></div>';
      }
    } catch (error) {
      notify(error.message, true);
    } finally {
      if (requestId === requestNumber) $(".results-panel").removeAttribute("aria-busy");
    }
  }
  $("#results").addEventListener("click", (event) => {
    const button = event.target.closest("[data-inspect]");
    if (button) select(button.dataset.inspect);
  });
  $("#prev-page").addEventListener("click", () => {
    if (page > 1) {
      page--;
      refresh();
    }
  });
  $("#next-page").addEventListener("click", () => {
    if (page * 10 < total) {
      page++;
      refresh();
    }
  });
  await refresh();
}

async function panorama() {
  const query = await initFilters(refresh);
  async function refresh(params = query()) {
    try {
      const stats = await api("/api/statistics?" + params);
      metrics(stats);
      renderCharts(stats);
    } catch (error) {
      notify(error.message, true);
    }
  }
  await refresh();
}

async function detail() {
  const root = $("#detail-content");
  try {
    const r = await api("/api/vulnerabilities/" + encodeURIComponent(document.body.dataset.cve));
    const nvd = r.nvd || {},
      assessments = nvd.assessments || [];
    const references = [
      ...new Set(
        [
          ...r.references,
          ...(nvd.references || []).map((ref) => ref.url),
          r.source_url,
          nvd.source_url,
        ]
          .map(safeUrl)
          .filter(Boolean),
      ),
    ];
    const description = nvd.descriptions?.find((item) => item.lang === "en")?.value;
    const configurations = nvd.configurations || [];
    const matches = configurations.flatMap((config) =>
      (config.nodes || []).flatMap((node) => node.cpeMatch || []),
    );
    root.innerHTML = `<section class="detail-hero"><div><h2>${e(r.cve_id)}</h2><p>${e(r.title)}</p><p>${e(r.vendor)} / ${e(r.product)}</p></div><div>${assessmentBadge(r)}<div style="margin-top:16px"><a class="button primary" href="${e(watchLink(r))}">Acompanhar este produto</a></div></div></section><div class="detail-layout"><div><section class="evidence-section" id="description"><h2>Descrição e ação recomendada</h2><h3>Descrição · CISA KEV</h3><p>${e(r.description)}</p><h3>Ação recomendada pela CISA</h3><p>${e(r.action)}</p>${description ? `<h3>Descrição · NVD</h3><p>${e(description)}</p>` : ""}<p class="field-hint">Conteúdo original da fonte. As instruções precisam ser avaliadas no contexto do ambiente afetado.</p></section><section class="evidence-section" id="cvss"><h2>Avaliações de severidade</h2><p class="context-note">CVSS mede severidade técnica, não o risco específico da sua organização. Avaliação principal: versão mais recente, Primary, NVD e fonte em ordem alfabética para desempate.</p>${assessments.length ? assessments.map((a) => `<article class="assessment"><div class="assessment-meta">${badge(a.severity)}<strong>${e(a.score)} / 10</strong><span>CVSS ${e(a.version)}</span><span class="muted">${e(a.type)}</span></div><p class="field-hint">Fonte: ${e(a.source)}</p><code>${e(a.vector)}</code><details><summary>Ver métricas da avaliação</summary><pre>${e(JSON.stringify(a.data, null, 2))}</pre></details></article>`).join("") : "<p>Sem avaliação disponível. Isso não significa severidade zero.</p>"}</section><section class="evidence-section" id="affected"><h2>Produtos e versões afetados</h2><p class="context-note">CPE identifica produtos. As faixas abaixo fazem parte de condições AND/OR da NVD; não são um diagnóstico do seu inventário.</p>${
      matches.length
        ? matches
            .map(
              (m) =>
                `<article class="assessment"><strong>${m.vulnerable ? "Produto vulnerável na condição" : "Condição de ambiente, não marcada como vulnerável"}</strong><code>${e(m.criteria)}</code><p>${
                  [
                    ["versionStartIncluding", "A partir de, inclusive"],
                    ["versionStartExcluding", "Depois de, exclusive"],
                    ["versionEndIncluding", "Até, inclusive"],
                    ["versionEndExcluding", "Antes de, exclusive"],
                  ]
                    .filter(([key]) => m[key])
                    .map(([key, label]) => `${e(label)}: ${e(m[key])}`)
                    .join(" · ") ||
                  "Versão descrita no identificador CPE; consulte as condições completas."
                }</p></article>`,
            )
            .join("")
        : "<p>Aplicabilidade não informada pela NVD.</p>"
    }<details><summary>Ver condições completas e identificadores CPE</summary><pre>${e(JSON.stringify(configurations, null, 2))}</pre></details></section><section class="evidence-section" id="references"><h2>Referências e fontes</h2><ul class="reference-list">${references.map((url) => `<li><a href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(url)}</a></li>`).join("")}</ul></section></div><aside class="detail-sidebar"><section class="evidence-section"><h2>Contexto da evidência</h2><dl><dt>Uso em ransomware</dt><dd>${r.ransomware === "Known" ? "Conhecido" : "Não confirmado pela CISA"}</dd><dt>Incluída no KEV</dt><dd>${date(r.date_added)}</dd><dt>Prazo informado pela CISA</dt><dd>${date(r.due_date)}</dd><dt>Fraquezas · CWE</dt><dd>${e(r.cwes.join(", ") || "Não informado")}</dd><dt>Estado NVD</dt><dd>${e(nvd.status || "Enriquecimento pendente")}</dd><dt>Publicação original · NVD</dt><dd>${timestamp(nvd.published)}</dd><dt>Modificação · NVD</dt><dd>${timestamp(nvd.last_modified)}</dd><dt>Primeira coleta</dt><dd>${timestamp(r.first_collected_at)}</dd><dt>Última coleta</dt><dd>${timestamp(r.last_collected_at)}</dd><dt>Último enriquecimento</dt><dd>${timestamp(r.nvd_updated_at)}</dd></dl></section><section class="evidence-section"><h2>Nesta investigação</h2><nav class="details-nav" aria-label="Seções da vulnerabilidade"><a href="#description">Descrição e ação</a><a href="#cvss">Avaliações CVSS</a><a href="#affected">Produtos e versões</a><a href="#references">Referências</a></nav></section></aside></div>`;
    const toc = $(".details-nav", root).closest("section");
    const sidebar = $(".detail-sidebar", root);
    const layout = $(".detail-layout", root);
    const compact = matchMedia("(max-width:960px)");
    toc.classList.add("detail-toc");
    const placeNavigation = () => (compact.matches ? layout.prepend(toc) : sidebar.append(toc));
    compact.addEventListener("change", placeNavigation);
    placeNavigation();
    const entries = $$("#affected .assessment", root);
    if (entries.length > 8) {
      const disclosure = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = `Ver mais ${entries.length - 8} condições de produto/ambiente`;
      disclosure.append(summary, ...entries.slice(8));
      $("#affected details", root).before(disclosure);
    }
    if (nvd.weaknesses?.length) {
      const section = document.createElement("section");
      section.className = "evidence-section";
      section.id = "weaknesses";
      section.innerHTML = `<h2>Classificações de fraqueza · NVD</h2>${nvd.weaknesses.map((w) => `<article class="assessment"><p>${e(w.source)} · ${e(w.type)}</p><p>${(w.description || []).map((d) => e(d.value) + ` (${e(d.lang)})`).join(" · ")}</p></article>`).join("")}`;
      $("#references", root).before(section);
    }
  } catch (error) {
    root.innerHTML = `<section class="evidence-section"><h2>Evidência não disponível</h2><p>${e(error.message)}</p><a href="/">Voltar ao catálogo</a></section>`;
  }
}

function safeNext(value) {
  try {
    const url = new URL(value || "/alertas", location.origin);
    return url.origin === location.origin ? url.pathname + url.search + url.hash : "/alertas";
  } catch {
    return "/alertas";
  }
}

function account() {
  const form = $("#account-form"),
    mode = form.dataset.mode;
  const next = safeNext(new URLSearchParams(location.search).get("next"));
  if (mode === "login")
    $(".account-alternate a").href = "/cadastrar?next=" + encodeURIComponent(next);
  else $(".account-alternate a").href = "/entrar?next=" + encodeURIComponent(next);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    action($("button", form), async () => {
      const email = $("#email").value,
        password = $("#password").value;
      if (mode === "login") {
        const result = await api("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
        session.csrf = result.csrf;
        location.assign(next);
      } else {
        await api("/api/auth/signup", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
        form.hidden = true;
        $("#confirm-form").hidden = false;
        $("#code").focus();
      }
    });
  });
  $("#confirm-form").addEventListener("submit", (event) => {
    event.preventDefault();
    action($("button", event.currentTarget), async () => {
      await api("/api/auth/confirm", {
        method: "POST",
        body: JSON.stringify({ email: $("#email").value, code: $("#code").value }),
      });
      location.assign("/entrar?next=" + encodeURIComponent(next));
    });
  });
}

async function alerts() {
  const products = await api("/api/products"),
    byKey = new Map(products.map((p) => [p.key, p]));
  let editing = null,
    subscriptions = [];
  const form = $("#subscription-form");
  $("#destination-hint").textContent = session.user.email;
  $("#product-options").innerHTML = products.length
    ? products
        .map(
          (p) =>
            `<label class="product-option" data-search="${e((p.vendor + " " + p.product).toLocaleLowerCase())}"><input type="checkbox" name="products" value="${e(p.key)}"><span><strong>${e(p.product)}</strong><small>${e(p.vendor)} · ${number(p.count)} registro(s)</small></span></label>`,
        )
        .join("")
    : '<p class="empty">A coleta ainda não trouxe produtos. Tente novamente após a primeira execução.</p>';
  const selection = () =>
    ($("#selection-count").textContent =
      `${$$("input[name=products]:checked", form).length} produto(s) selecionado(s)`);
  $("#product-options").addEventListener("change", selection);
  $("#product-search").addEventListener("input", (event) =>
    $$(".product-option").forEach(
      (row) => (row.hidden = !row.dataset.search.includes(event.target.value.toLocaleLowerCase())),
    ),
  );
  $("#destination").addEventListener("change", () => {
    $("#other-email").hidden = $("#destination").value !== "other";
    $("#subscription-email").required = !$("#other-email").hidden;
    $("#subscription-email").disabled = $("#other-email").hidden;
  });
  const watch = new URLSearchParams(location.search).get("watch");
  if (watch) {
    const checkbox = $$("input[name=products]", form).find((input) => input.value === watch);
    if (checkbox) {
      checkbox.checked = true;
      if (!$("#subscription-name").value) $("#subscription-name").value = byKey.get(watch).product;
      selection();
    }
  }
  function reset() {
    editing = null;
    form.reset();
    $("#other-email").hidden = true;
    $("#subscription-email").required = false;
    $("#subscription-email").disabled = true;
    $("#subscription-form-title").textContent = "Criar assinatura";
    $("#cancel-edit").hidden = true;
    $$(".product-option").forEach((row) => (row.hidden = false));
    selection();
  }
  $("#new-subscription").addEventListener("click", () => {
    reset();
    $("#subscription-name").focus();
  });
  $("#cancel-edit").addEventListener("click", reset);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    action($("button[type=submit]", form), async () => {
      const chosen = $$("input[name=products]:checked", form).map((input) => input.value);
      if (!chosen.length) throw new Error("Selecione pelo menos um produto para acompanhar.");
      const body = {
        name: $("#subscription-name").value,
        products: chosen,
        email: $("#destination").value === "other" ? $("#subscription-email").value : null,
        changes: $("#subscription-changes").checked,
        enabled: $("#subscription-enabled").checked,
      };
      await api("/api/subscriptions" + (editing ? "/" + editing : ""), {
        method: editing ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      reset();
      notify("Assinatura salva. Você receberá os próximos eventos dos produtos escolhidos.");
      await refresh();
    });
  });
  $("#subscriptions-list").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const sub = subscriptions.find((s) => s.id === button.dataset.id);
    if (button.dataset.action === "edit") {
      editing = sub.id;
      $("#subscription-name").value = sub.name;
      $("#destination").value = sub.email === session.user.email ? "account" : "other";
      $("#destination").dispatchEvent(new Event("change"));
      $("#subscription-email").value = sub.email;
      $("#subscription-changes").checked = sub.changes;
      $("#subscription-enabled").checked = sub.enabled;
      $$("input[name=products]", form).forEach(
        (input) => (input.checked = sub.products.includes(input.value)),
      );
      $("#subscription-form-title").textContent = "Editar assinatura";
      $("#cancel-edit").hidden = false;
      selection();
      $("#subscription-name").focus();
      return;
    }
    action(button, async () => {
      if (button.dataset.action === "delete") {
        if (!confirm("Excluir esta assinatura? Novos alertas deixarão de ser enviados.")) return;
        await api("/api/subscriptions/" + sub.id, { method: "DELETE" });
        notify("Assinatura excluída.");
      } else {
        await api(`/api/subscriptions/${sub.id}/test`, { method: "POST" });
        notify("Teste agendado. Confira o histórico e o Mailpit após o envio pelo worker.");
      }
      await refresh();
    });
  });
  async function refresh() {
    const [subs, history] = await Promise.all([api("/api/subscriptions"), api("/api/alerts")]);
    subscriptions = subs;
    $("#subscriptions-count").textContent = `${subs.length} assinatura(s)`;
    $("#subscriptions-list").innerHTML = subs.length
      ? subs
          .map(
            (s) =>
              `<article class="subscription-entry"><header><h3>${e(s.name)}</h3><span class="badge">${s.enabled ? "Ativa" : "Pausada"}</span></header><p>Destino: ${e(s.email)}</p><div class="product-tags">${s.products
                .map((key) => {
                  const p = byKey.get(key);
                  return `<span class="product-tag">${e(p ? p.vendor + " / " + p.product : key)}</span>`;
                })
                .join(
                  "",
                )}</div><p style="margin-top:12px">${s.changes ? "Novos registros e alterações" : "Apenas novos registros"} · Sem envio retroativo</p><div class="entry-actions"><button class="button subtle" data-id="${e(s.id)}" data-action="edit">Editar</button><button class="button subtle" data-id="${e(s.id)}" data-action="test" ${s.enabled ? "" : "disabled"}>Testar e-mail</button><button class="button subtle danger" data-id="${e(s.id)}" data-action="delete">Excluir</button></div></article>`,
          )
          .join("")
      : '<div class="empty"><h2>Você ainda não acompanha produtos</h2><p>Crie sua primeira assinatura para receber novos alertas.</p></div>';
    $("#alerts-history").innerHTML = history.length
      ? history
          .map(
            (a) =>
              `<article class="alert-entry"><header><strong>${e(a.name)}</strong>${badge(a.status)}</header><p>${timestamp(a.created_at)} · ${e(a.email)} · ${a.attempts} tentativa(s)</p><details><summary>${a.items.length} registro(s)${a.items.some((i) => i.simulated) ? " · DEMONSTRAÇÃO" : ""}</summary><ul>${a.items.map((i) => `<li>${i.simulated ? e(i.cve_id) + " · sintético" : `<a href="/vulnerabilidades/${encodeURIComponent(i.cve_id)}">${e(i.cve_id)}</a>`} — ${e(i.vendor)} / ${e(i.product)} · ${i.event === "new" ? "Novo" : "Alterado"}<br>${e(i.title)}</li>`).join("")}</ul>${a.error ? `<p>Falha: ${e(a.error)}</p>` : ""}</details></article>`,
          )
          .join("")
      : '<p class="empty">Seu histórico aparecerá quando houver um evento ou envio de teste.</p>';
  }
  await refresh();
  setInterval(() => {
    if (!document.hidden) refresh().catch((error) => notify(error.message, true));
  }, 10000);
}

async function admin() {
  const products = await api("/api/products");
  products.forEach((p) =>
    $("#simulate-product").add(new Option(`${p.vendor} / ${p.product}`, p.key)),
  );
  let initialized = false;
  async function refresh() {
    const [status, runs, deliveries] = await Promise.all([
      api("/api/admin/status"),
      api("/api/admin/runs"),
      api("/api/admin/deliveries"),
    ]);
    $("#admin-summary").innerHTML = [
      [number(status.records), "Registros reais"],
      [status.schedule.baseline_completed ? "Pronta" : "Inicial", "Base de alertas"],
      [number(status.deliveries.pending || 0), "E-mails pendentes"],
      [number(status.deliveries.sent || 0), "E-mails enviados"],
    ]
      .map(([v, l]) => `<div class="metric"><strong>${e(v)}</strong><span>${e(l)}</span></div>`)
      .join("");
    if (!initialized) {
      $("#schedule-enabled").checked = status.schedule.enabled;
      $("#interval-hours").value = status.schedule.interval_hours;
      $("#schedule-pages").value = status.schedule.max_pages;
      initialized = true;
    }
    $("#next-run").textContent = status.schedule.enabled
      ? "Próxima execução: " + timestamp(status.schedule.next_run_at)
      : "Programação pausada. Execuções manuais continuam disponíveis.";
    $("#runs-table").innerHTML = runs.length
      ? runs
          .map(
            (r) =>
              `<tr><td>${timestamp(r.started_at || r.created_at)}<br><span class="muted">${r.requested_by === "schedule" ? "Programada" : r.requested_by === "cli" ? "Comando manual" : "Admin"}${r.baseline ? " · carga inicial" : ""}</span></td><td>${badge(r.status)}</td><td>${number(r.progress.pages)}</td><td>${number(r.progress.new)}</td><td>${number(r.progress.changed)}</td><td>${number(r.progress.enriched)}</td><td class="error-cell">${e(r.error || r.warning || (r.status === "completed" ? "Coleta concluída" : "—"))}</td></tr>`,
          )
          .join("")
      : '<tr><td colspan="7" class="empty">Nenhuma execução registrada. Solicite uma coleta.</td></tr>';
    $("#deliveries-table").innerHTML = deliveries.length
      ? deliveries
          .map(
            (d) =>
              `<tr><td><strong>${e(d.name)}</strong><br>${e(d.email)}${d.items.some((i) => i.simulated) ? "<br>DEMONSTRAÇÃO" : ""}</td><td>${badge(d.status)}</td><td>${d.items.length}</td><td>${d.attempts}</td><td class="error-cell">${e(d.error || "—")}${d.status === "failed" ? `<br><button class="button subtle" data-retry="${e(d.id)}">Tentar novamente</button>` : ""}</td></tr>`,
          )
          .join("")
      : '<tr><td colspan="5" class="empty">Nenhuma entrega registrada.</td></tr>';
  }
  $("#schedule-form").addEventListener("submit", (event) => {
    event.preventDefault();
    action($("button", event.currentTarget), async () => {
      await api("/api/admin/schedule", {
        method: "PUT",
        body: JSON.stringify({
          enabled: $("#schedule-enabled").checked,
          interval_hours: Number($("#interval-hours").value),
          max_pages: Number($("#schedule-pages").value),
        }),
      });
      notify("Programação atualizada.");
      await refresh();
    });
  });
  $("#run-form").addEventListener("submit", (event) => {
    event.preventDefault();
    action($("button", event.currentTarget), async () => {
      await api("/api/admin/runs", {
        method: "POST",
        body: JSON.stringify({ max_pages: Number($("#run-pages").value) }),
      });
      notify("Execução solicitada. Acompanhe o progresso na tabela.");
      await refresh();
    });
  });
  $("#simulation-form").addEventListener("submit", (event) => {
    event.preventDefault();
    action($("button", event.currentTarget), async () => {
      await api("/api/admin/simulate", {
        method: "POST",
        body: JSON.stringify({ product_key: $("#simulate-product").value }),
      });
      notify("Evento sintético criado. Assinaturas ativas correspondentes receberão o alerta.");
      await refresh();
    });
  });
  $("#refresh-admin").addEventListener("click", (event) => action(event.currentTarget, refresh));
  $("#deliveries-table").addEventListener("click", (event) => {
    const button = event.target.closest("[data-retry]");
    if (button)
      action(button, async () => {
        await api("/api/admin/deliveries/" + encodeURIComponent(button.dataset.retry) + "/retry", {
          method: "POST",
        });
        await refresh();
      });
  });
  await refresh();
  setInterval(() => {
    if (!document.hidden) refresh().catch((error) => notify(error.message, true));
  }, 10000);
}

async function start() {
  $("#notice-close").addEventListener("click", () => ($("#notice").hidden = true));
  session = await api("/api/session");
  if (session.user) {
    $("#account-nav").innerHTML =
      `<span class="account-email">${e(session.user.email)}</span><button id="logout" type="button">Sair</button>`;
    $("#admin-link").hidden = !session.user.admin;
    $("#logout").addEventListener("click", (event) =>
      action(event.currentTarget, async () => {
        await api("/api/auth/logout", { method: "POST" });
        location.assign("/");
      }),
    );
  }
  const view = document.body.dataset.view;
  if (view === "workbench") await workbench();
  else if (view === "panorama") await panorama();
  else if (view === "detail") await detail();
  else if (view === "login" || view === "signup") account();
  else if (view === "alerts") await alerts();
  else if (view === "admin") await admin();
}
start()
  .catch((error) => notify(error.message, true))
  .finally(() => {
    $("#app-controls").disabled = false;
    $("#main").inert = false;
  });
