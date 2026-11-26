/* PIXELTRUTH Custom Frontend Controller (100% Local & Offline) */
(function () {
  "use strict";

  const state = {
    sessionId: null,
    inspection: null,
    objectUrl: null,
    gpsResult: null,
    elaResult: null,
    histResult: null,
    cmpAUrl: null,
    cmpBUrl: null,
    cmpAInfo: null,
    cmpBInfo: null,
  };

  function $(id) {
    return document.getElementById(id);
  }

  function apiHeaders(extra) {
    const h = Object.assign({}, extra || {});
    if (state.sessionId) {
      h["X-Pixeltruth-Session"] = state.sessionId;
    }
    return h;
  }

  function navigateTo(screenId) {
    document.querySelectorAll(".screen").forEach((el) => {
      el.classList.toggle("active", el.dataset.screen === screenId);
    });
    document.querySelectorAll(".nav-link[data-nav]").forEach((btn) => {
      const target = btn.dataset.nav;
      if (target === screenId) {
        btn.setAttribute("aria-current", "page");
      } else {
        btn.removeAttribute("aria-current");
      }
    });
    const sidebar = $("app-sidebar");
    if (sidebar && sidebar.classList.contains("open")) {
      sidebar.classList.remove("open");
      const toggle = $("mobile-nav-toggle");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    }
  }

  function openGpsSection() {
    navigateTo("metadata-explorer");
    const gpsDetails = $("gps-section");
    if (gpsDetails) {
      gpsDetails.setAttribute("open", "");
      gpsDetails.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  document.querySelectorAll("[data-nav]").forEach((el) => {
    el.addEventListener("click", () => {
      const dest = el.dataset.nav;
      if (dest === "gps-information") {
        openGpsSection();
      } else {
        navigateTo(dest);
      }
    });
  });

  const mobileToggle = $("mobile-nav-toggle");
  if (mobileToggle) {
    mobileToggle.addEventListener("click", () => {
      const sidebar = $("app-sidebar");
      const isOpen = sidebar.classList.toggle("open");
      mobileToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
  }

  function updateStatusPills() {
    const text = state.inspection
      ? "Active: " + state.inspection.properties.filename
      : "Status: Awaiting image input";
    document.querySelectorAll("[data-status-pill]").forEach((pill) => {
      pill.textContent = text;
      pill.classList.toggle("active-file", Boolean(state.inspection));
    });
  }

  function renderRecent(records) {
    const tbody = $("recent-table-body");
    const countEl = $("recent-count");
    countEl.textContent = records.length + (records.length === 1 ? " record" : " records");
    tbody.innerHTML = "";
    if (!records.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.style.textAlign = "center";
      td.style.padding = "32px";
      td.className = "muted";
      td.textContent = "No analyses recorded in this session. Upload an image above to populate local session records.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    records.forEach((rec) => {
      const tr = document.createElement("tr");
      [rec.filename, rec.format, rec.dimensions, rec.sha256_prefix, rec.timestamp_utc].forEach((val, idx) => {
        const td = document.createElement("td");
        if (idx >= 2) td.className = "mono tabular";
        td.textContent = val;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  function renderImageAnalysis() {
    const data = state.inspection;
    $("ia-empty").classList.toggle("hidden", Boolean(data));
    $("ia-content").classList.toggle("hidden", !data);
    if (!data) return;

    const p = data.properties;
    const warnBox = $("ia-warnings");
    warnBox.innerHTML = "";
    data.warnings.forEach((w) => {
      const div = document.createElement("div");
      div.className = "notice-bar error";
      div.textContent = w;
      warnBox.appendChild(div);
    });

    if (state.objectUrl) {
      $("ia-preview-img").src = state.objectUrl;
      $("ela-orig-img").src = state.objectUrl;
    }
    $("ia-preview-name").textContent = p.filename;
    $("ia-preview-dims").textContent = p.width + " × " + p.height;

    $("prop-format").textContent = p.image_format;
    $("prop-mime").textContent = p.mime_type;
    $("prop-dims").textContent = p.width + " × " + p.height + " px";
    $("prop-mp").textContent = p.megapixels.toFixed(2) + " megapixels";
    $("prop-size").textContent = (p.file_size_bytes / (1024 * 1024)).toFixed(2) + " MB";
    $("prop-bytes").textContent = p.file_size_bytes.toLocaleString() + " bytes";
    $("prop-color").textContent = p.color_mode;
    $("prop-depth").textContent = p.bit_depth_per_channel ? p.bit_depth_per_channel + "-bit per channel" : "Bit depth unavailable";
    $("prop-aspect").textContent = p.aspect_ratio.toFixed(3) + ":1";
    $("prop-frames").textContent = p.frame_count + " frame(s)";
    $("prop-orientation").textContent = p.orientation;
    $("prop-transparency").textContent = p.has_transparency ? "Transparency present" : "No transparency";
    $("sha256-value").textContent = data.sha256;

    renderMalwareScan(data.malware_scan);
  }

  function renderMalwareScan(ms) {
    const card = $("malware-scan-card");
    const titleEl = $("malware-scan-title");
    const badgeEl = $("malware-scan-badge");
    const descEl = $("malware-scan-desc");
    const noticeEl = $("malware-scan-notice");
    const metaEl = $("malware-scan-meta");
    const detGroup = $("malware-detections-group");
    const detCountEl = $("malware-detections-count");
    const detListEl = $("malware-detections-list");
    const msgEl = $("malware-scan-messages");
    const limEl = $("malware-scan-limitations");

    card.classList.remove("malware-status-clean", "malware-status-detected", "malware-status-incomplete");
    badgeEl.classList.remove("malware-badge-clean", "malware-badge-detected", "malware-badge-incomplete");
    noticeEl.className = "notice-bar hidden";
    noticeEl.textContent = "";
    metaEl.innerHTML = "";
    detListEl.innerHTML = "";
    detGroup.classList.add("hidden");
    msgEl.innerHTML = "";
    limEl.innerHTML = "";

    const addMetaItem = (label, value, isMono = false) => {
      if (value === null || value === undefined || value === "") return;
      const item = document.createElement("div");
      item.className = "malware-meta-item";
      const lbl = document.createElement("span");
      lbl.className = "small-copy";
      lbl.textContent = label;
      const val = document.createElement("span");
      val.className = isMono ? "mono tabular" : "";
      val.style.fontSize = "13px";
      val.style.color = "#FFFFFF";
      val.textContent = String(value);
      item.appendChild(lbl);
      item.appendChild(val);
      metaEl.appendChild(item);
    };

    const appendNotice = (text, isError = false) => {
      if (!text) return;
      const div = document.createElement("div");
      div.className = isError ? "notice-bar error" : "notice-bar";
      div.textContent = String(text);
      msgEl.appendChild(div);
    };

    if (!ms || typeof ms !== "object") {
      card.classList.add("malware-status-incomplete");
      badgeEl.classList.add("malware-badge-incomplete");
      badgeEl.textContent = "UNAVAILABLE";
      titleEl.textContent = "Scan status unavailable";
      descEl.textContent = "Malware scan data was not provided. The file's malware status is unknown.";
      return;
    }

    const status = ms.scan_status;
    if (status === "NO_KNOWN_THREAT") {
      card.classList.add("malware-status-clean");
      badgeEl.classList.add("malware-badge-clean");
      badgeEl.textContent = "NO KNOWN THREAT";
      titleEl.textContent = "No known threat detected";
      descEl.textContent = "ClamAV completed the scan and did not detect any known malware signatures.";
    } else if (status === "MALWARE_DETECTED") {
      card.classList.add("malware-status-detected");
      badgeEl.classList.add("malware-badge-detected");
      badgeEl.textContent = "MALWARE DETECTED";
      titleEl.textContent = "Malware detected";
      descEl.textContent = "A known malware signature was detected during the scan.";
      noticeEl.className = "notice-bar error";
      noticeEl.textContent = "ClamAV detected a known malware signature in this file. Do not open or execute this file.";
    } else if (status === "SCAN_INCOMPLETE") {
      card.classList.add("malware-status-incomplete");
      badgeEl.classList.add("malware-badge-incomplete");
      badgeEl.textContent = "SCAN INCOMPLETE";
      titleEl.textContent = "Scan incomplete";
      descEl.textContent = "The image could not be reliably checked for known malware signatures.";
      const reasonLabels = {
        CLAMAV_NOT_INSTALLED: "ClamAV is not installed or could not be located.",
        INVALID_EXECUTABLE_PATH: "Configured ClamAV executable path is invalid.",
        DATABASE_MISSING: "ClamAV signature database is missing or unreadable.",
        DATABASE_OUTDATED: "ClamAV signature database is outdated.",
        SCAN_TIMEOUT: "ClamAV scan timed out.",
        MALFORMED_OUTPUT: "ClamAV returned malformed or unparseable output.",
        EXECUTION_ERROR: "ClamAV execution failed.",
        UNEXPECTED_EXIT_STATUS: "ClamAV exited with an unexpected status code.",
        UNEXPECTED_ERROR: "An unexpected internal scanner error occurred.",
        SCAN_UNAVAILABLE: "Malware scan result is unavailable.",
      };
      if (ms.reason_code && reasonLabels[ms.reason_code]) {
        noticeEl.className = "notice-bar";
        noticeEl.textContent = reasonLabels[ms.reason_code];
      }
    } else {
      card.classList.add("malware-status-incomplete");
      badgeEl.classList.add("malware-badge-incomplete");
      badgeEl.textContent = "UNAVAILABLE";
      titleEl.textContent = "Scan status unavailable";
      descEl.textContent = "Malware scan returned an unrecognized status. The file's malware status is unknown.";
    }

    addMetaItem("Scanner", ms.scanner_name || "ClamAV");
    addMetaItem("Scanner Version", ms.scanner_version, true);
    addMetaItem("Database Version", ms.signature_database_version, true);
    addMetaItem("Database Freshness", ms.database_freshness);
    if (typeof ms.scan_duration === "number") {
      addMetaItem("Scan Duration", ms.scan_duration.toFixed(2) + " s", true);
    }
    if (status === "MALWARE_DETECTED") {
      const count = typeof ms.detection_count === "number" ? ms.detection_count : (Array.isArray(ms.detections) ? ms.detections.length : 0);
      addMetaItem("Detections", String(count), true);
    }
    if (status === "SCAN_INCOMPLETE" && ms.reason_code) {
      addMetaItem("Reason Code", ms.reason_code, true);
    }
    metaEl.classList.toggle("hidden", metaEl.children.length === 0);

    const detections = Array.isArray(ms.detections) ? ms.detections : [];
    if (status === "MALWARE_DETECTED" && detections.length > 0) {
      detGroup.classList.remove("hidden");
      detGroup.open = true;
      detCountEl.textContent = detections.length + (detections.length === 1 ? " detection" : " detections");
      detections.forEach((det) => {
        const box = document.createElement("div");
        box.className = "malware-detection-item";

        const nameLine = document.createElement("div");
        nameLine.className = "mono";
        nameLine.style.color = "#FFFFFF";
        nameLine.style.fontWeight = "600";
        nameLine.textContent = det && det.detection_name ? String(det.detection_name) : "Unknown detection";
        box.appendChild(nameLine);

        const subParts = [];
        if (det && det.threat_category) subParts.push("Category: " + det.threat_category);
        if (det && det.scanner_verdict) subParts.push("Verdict: " + det.scanner_verdict);
        if (subParts.length) {
          const sub = document.createElement("div");
          sub.className = "small-copy";
          sub.textContent = subParts.join(" · ");
          box.appendChild(sub);
        }
        if (det && det.additional_details) {
          const detail = document.createElement("div");
          detail.className = "small-copy mono";
          detail.textContent = String(det.additional_details);
          box.appendChild(detail);
        }
        detListEl.appendChild(box);
      });
    }

    (Array.isArray(ms.errors) ? ms.errors : []).forEach((err) => appendNotice(err, status === "MALWARE_DETECTED"));
    (Array.isArray(ms.warnings) ? ms.warnings : []).forEach((warn) => appendNotice(warn, false));
    (Array.isArray(ms.limitations) ? ms.limitations : []).forEach((lim) => {
      const p = document.createElement("p");
      p.className = "small-copy";
      p.style.margin = "2px 0";
      p.textContent = "• " + String(lim);
      limEl.appendChild(p);
    });
  }

  function renderMetadataAndAssessment() {
    const data = state.inspection;
    $("me-empty").classList.toggle("hidden", Boolean(data));
    $("me-content").classList.toggle("hidden", !data);
    if (!data) return;

    const a = data.assessment;
    $("assess-badge").textContent = a.outcome;
    $("assess-explanation").textContent = a.outcome_explanation;

    const findingsBox = $("assess-findings");
    findingsBox.innerHTML = "";
    if (!a.findings.length) {
      const p = document.createElement("p");
      p.className = "small-copy";
      p.textContent = "No findings were emitted by the registered assessment rules.";
      findingsBox.appendChild(p);
    } else {
      a.findings.forEach((f) => {
        const det = document.createElement("details");
        det.className = "meta-group";
        det.open = true;
        const sum = document.createElement("summary");
        const titleSpan = document.createElement("span");
        titleSpan.textContent = f.title;
        const relSpan = document.createElement("span");
        relSpan.className = "badge";
        relSpan.textContent = f.relevance;
        sum.appendChild(titleSpan);
        sum.appendChild(relSpan);
        det.appendChild(sum);

        const body = document.createElement("div");
        body.style.padding = "14px 20px";
        body.style.display = "flex";
        body.style.flexDirection = "column";
        body.style.gap = "6px";
        [
          ["Provenance", `rule_id=${f.rule_id} · finding_id=${f.finding_id} · check_id=${f.check_id}`],
          ["Observed evidence", f.observed_evidence],
          ["Explanation", f.explanation],
          ["Possible interpretations", f.possible_interpretations],
          ["Limitations", f.limitations],
          ["Recommended next check", f.recommended_next_check],
        ].forEach(([k, v]) => {
          const line = document.createElement("p");
          line.className = "small-copy";
          const strong = document.createElement("strong");
          strong.style.color = "#FFFFFF";
          strong.textContent = k + ": ";
          line.appendChild(strong);
          line.appendChild(document.createTextNode(v));
          body.appendChild(line);
        });
        det.appendChild(body);
        findingsBox.appendChild(det);
      });
    }

    const applicableCount = a.evaluations.filter((ev) => ev.applicability === "APPLICABLE").length;
    const evaluatedCount = a.evaluations.filter((ev) => ev.coverage_state === "EVALUATED_WITH_FINDING" || ev.coverage_state === "EVALUATED_WITHOUT_FINDING").length;
    const notAppCount = a.evaluations.length - applicableCount;
    $("assess-eval-count").textContent = `${applicableCount} applicable (${evaluatedCount} evaluated) · ${notAppCount} not applicable (${a.evaluations.length} total)`;
    const evalBody = $("assess-eval-body");
    evalBody.innerHTML = "";
    a.evaluations.forEach((ev) => {
      const tr = document.createElement("tr");
      [ev.evaluation_id, ev.applicability, ev.coverage_state, ev.coverage_reason].forEach((val, idx) => {
        const td = document.createElement("td");
        if (idx === 0) td.className = "mono";
        td.textContent = val;
        tr.appendChild(td);
      });
      evalBody.appendChild(tr);
    });

    const limBox = $("assess-limitations");
    limBox.innerHTML = "";
    a.limitations.forEach((note) => {
      const p = document.createElement("p");
      p.className = "small-copy";
      p.style.margin = "2px 0";
      p.textContent = "• " + note;
      limBox.appendChild(p);
    });

    // Render Image Information summary, Extraction Coverage & Dynamic Metadata Explorer
    renderImageInfoSummary(data);
    renderCoverage(data.inventory);
    populateFilterOptions(data.inventory);
    renderMetadataGroups();

    // Reset GPS UI on new upload
    renderGpsState();
  }

  function renderImageInfoSummary(data) {
    const grid = $("meta-image-summary-grid");
    if (!grid) return;
    grid.innerHTML = "";
    const p = data.properties;
    const records = (data.inventory && Array.isArray(data.inventory.records)) ? data.inventory.records : [];
    const findRec = (id) => records.find((r) => r.record_id === id);

    const channelsRec = findRec("container:image:ColourChannels");
    const dpiRec = findRec("container:info:dpi");
    const items = [
      ["Dimensions", `${p.width} × ${p.height} px`],
      ["Colour mode", p.color_mode],
      ["Channels", channelsRec ? String(channelsRec.raw_value) : "Unavailable"],
      ["Bit depth", p.bit_depth_per_channel ? `${p.bit_depth_per_channel} bits per channel` : "Unavailable"],
      ["Frames", String(p.frame_count)],
      ["Transparency", p.has_transparency ? "Yes" : "No"],
      ["Resolution", dpiRec ? dpiRec.interpreted_value : "Unavailable"],
    ];
    items.forEach(([label, value]) => {
      const box = document.createElement("div");
      box.className = "malware-meta-item";
      const lbl = document.createElement("span");
      lbl.className = "small-copy";
      lbl.textContent = label;
      const val = document.createElement("span");
      val.className = "mono tabular";
      val.style.fontSize = "13px";
      val.style.color = "#FFFFFF";
      val.textContent = value;
      box.appendChild(lbl);
      box.appendChild(val);
      grid.appendChild(box);
    });
  }

  function renderCoverage(inv) {
    const summaryEl = $("meta-coverage-summary");
    const warnEl = $("meta-coverage-warnings");
    const stageBody = $("meta-stage-body");
    const stageCount = $("meta-stage-count");
    const limEl = $("meta-coverage-limitations");

    warnEl.innerHTML = "";
    stageBody.innerHTML = "";

    if (!inv || !inv.coverage) {
      summaryEl.textContent = "Inventory unavailable";
      stageCount.textContent = "0 stages";
      limEl.textContent = "";
      return;
    }

    const cov = inv.coverage;
    const unsupportedText = cov.unsupported_sources.length
      ? " · Unsupported: " + cov.unsupported_sources.join(", ")
      : "";
    const capText = cov.format_capability
      ? ` · Capability: ${cov.format_capability.support_level}`
      : "";
    summaryEl.textContent = `${cov.total_records} records · ${cov.categories_found.length} categories${capText}${unsupportedText}`;
    stageCount.textContent = `${cov.stages.length} engines/stages`;

    cov.warnings.forEach((w) => {
      const div = document.createElement("div");
      div.className = "notice-bar";
      div.textContent = `[${w.stage_id}] ${w.code}: ${w.message}`;
      warnEl.appendChild(div);
    });

    cov.stages.forEach((st) => {
      const tr = document.createElement("tr");
      const notes = [
        ...(st.errors || []),
        ...st.warnings.map((w) => w.message),
        ...st.unsupported_features,
        ...(st.skipped_sections || []),
        ...st.limitations,
      ].join(" ");
      const durText = typeof st.duration_ms === "number" ? `${st.duration_ms.toFixed(1)} ms` : "—";
      [
        st.stage_id,
        st.engine_name || st.source_standard,
        st.engine_version || "—",
        st.availability || "Available",
        st.completion_state,
        durText,
        String(st.records_extracted),
        notes || "—",
      ].forEach((val, idx) => {
        const td = document.createElement("td");
        if (idx === 0 || idx === 2 || idx === 5 || idx === 6) td.className = "mono tabular";
        td.textContent = val;
        tr.appendChild(td);
      });
      stageBody.appendChild(tr);
    });

    limEl.textContent = cov.limitations.join(" ");
  }

  function populateFilterOptions(inv) {
    const records = inv ? inv.records : [];
    const fill = (id, label, values) => {
      const sel = $(id);
      sel.innerHTML = "";
      const allOpt = document.createElement("option");
      allOpt.value = "";
      allOpt.textContent = label;
      sel.appendChild(allOpt);
      Array.from(new Set(values)).forEach((v) => {
        const opt = document.createElement("option");
        opt.value = v;
        opt.textContent = v;
        sel.appendChild(opt);
      });
    };
    fill("meta-filter-source", "All sources", records.map((r) => r.source));
    fill("meta-filter-category", "All categories", records.map((r) => r.category));
    fill("meta-filter-type", "All types", records.map((r) => r.data_type));
    fill("meta-filter-status", "All statuses", records.map((r) => r.status));
  }

  function getFilteredRecords() {
    const inv = state.inspection && state.inspection.inventory;
    if (!inv) return [];
    const q = $("meta-search").value.trim().toLowerCase();
    const src = $("meta-filter-source").value;
    const cat = $("meta-filter-category").value;
    const dtype = $("meta-filter-type").value;
    const status = $("meta-filter-status").value;

    return inv.records.filter((r) => {
      if (src && r.source !== src) return false;
      if (cat && r.category !== cat) return false;
      if (dtype && r.data_type !== dtype) return false;
      if (status && r.status !== status) return false;
      if (!q) return true;
      const haystack = [
        r.tag_name,
        r.tag_id || "",
        r.namespace || "",
        (r.path || []).join(" "),
        r.interpreted_value || "",
        typeof r.raw_value === "string" ? r.raw_value : JSON.stringify(r.raw_value ?? ""),
        r.limitations || "",
      ].join(" ").toLowerCase();
      return haystack.includes(q);
    });
  }

  function copyTextWithFeedback(btn, text, defaultLabel) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = defaultLabel; }, 1200);
  }

  function renderMetadataGroups() {
    const container = $("metadata-groups");
    container.innerHTML = "";
    const inv = state.inspection && state.inspection.inventory;
    const filtered = getFilteredRecords();
    $("meta-match-count").textContent = `Showing ${filtered.length} of ${inv ? inv.records.length : 0} records`;
    $("meta-empty-filter").classList.toggle("hidden", filtered.length > 0);
    if (!filtered.length) return;

    const grouped = new Map();
    filtered.forEach((rec) => {
      if (!grouped.has(rec.category)) grouped.set(rec.category, []);
      grouped.get(rec.category).push(rec);
    });

    let groupIndex = 0;
    grouped.forEach((records, categoryTitle) => {
      const det = document.createElement("details");
      det.className = "meta-group";
      if (groupIndex < 3 || $("meta-search").value.trim()) det.open = true;
      groupIndex++;

      const sum = document.createElement("summary");
      const left = document.createElement("span");
      left.textContent = categoryTitle;
      const right = document.createElement("span");
      right.className = "small-copy mono tabular";
      right.textContent = records.length + (records.length === 1 ? " field" : " fields");
      sum.appendChild(left);
      sum.appendChild(right);
      det.appendChild(sum);

      records.forEach((r) => {
        const recDet = document.createElement("details");
        recDet.className = "meta-record";

        const recSum = document.createElement("summary");
        const main = document.createElement("div");
        main.className = "meta-record-main";
        const nameEl = document.createElement("span");
        nameEl.className = "meta-record-name";
        nameEl.textContent = r.tag_name;
        const valEl = document.createElement("span");
        valEl.className = "meta-record-val";
        valEl.textContent = r.interpreted_value || "Not interpreted";
        main.appendChild(nameEl);
        main.appendChild(valEl);

        const actions = document.createElement("div");
        actions.className = "meta-record-actions";
        if (r.is_unknown) {
          const unkBadge = document.createElement("span");
          unkBadge.className = "badge";
          unkBadge.textContent = "Unknown";
          actions.appendChild(unkBadge);
        }
        const srcBadge = document.createElement("span");
        srcBadge.className = "badge";
        srcBadge.textContent = r.source;
        actions.appendChild(srcBadge);

        if (r.status !== "Present") {
          const stBadge = document.createElement("span");
          stBadge.className = "badge badge-light";
          stBadge.textContent = r.status;
          actions.appendChild(stBadge);
        }

        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "btn btn-sm";
        copyBtn.textContent = "Copy";
        copyBtn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          copyTextWithFeedback(copyBtn, r.interpreted_value || JSON.stringify(r.raw_value ?? ""), "Copy");
        });
        actions.appendChild(copyBtn);

        recSum.appendChild(main);
        recSum.appendChild(actions);
        recDet.appendChild(recSum);

        const body = document.createElement("div");
        body.className = "meta-record-body";
        const grid = document.createElement("div");
        grid.className = "meta-kv-grid";
        let rawDisplay;
        if (r.raw_value === null || r.raw_value === undefined) {
          rawDisplay = "—";
        } else if (typeof r.raw_value === "object" && !Array.isArray(r.raw_value) && "byte_length" in r.raw_value) {
          rawDisplay = `Binary data (${r.raw_value.byte_length} bytes)`;
        } else if (typeof r.raw_value === "string") {
          rawDisplay = r.raw_value;
        } else {
          rawDisplay = JSON.stringify(r.raw_value);
        }
        [
          ["Source Engine", r.source_engine || r.source || "—"],
          ["Source Container", r.source_container || "—"],
          ["Category", r.category || "—"],
          ["Tag ID", r.tag_id || "—"],
          ["Namespace", r.namespace || "—"],
          ["Path", (r.path || []).join(" / ") || "—"],
          ["Data Type / Status", `${r.data_type || "unknown"} · ${r.extraction_status || r.status || "Unknown"}`],
          ["Raw Value", rawDisplay],
          ["Interpreted Value", r.interpreted_value || "Not interpreted"],
          ["Discovered By", Array.isArray(r.discovered_by) && r.discovered_by.length ? r.discovered_by.join(", ") : (r.source_engine || r.source || "—")],
          ...(r.engine_disagreement ? [["Engine Disagreement", r.engine_disagreement]] : []),
          ["Limitations", r.limitations || "None"],
        ].forEach(([lbl, val]) => {
          const kv = document.createElement("div");
          kv.className = "meta-kv";
          const lEl = document.createElement("div");
          lEl.className = "meta-kv-label";
          lEl.textContent = lbl;
          const vEl = document.createElement("div");
          vEl.className = "meta-kv-val";
          vEl.textContent = String(val);
          kv.appendChild(lEl);
          kv.appendChild(vEl);
          grid.appendChild(kv);
        });
        body.appendChild(grid);

        const copyRecBtn = document.createElement("button");
        copyRecBtn.type = "button";
        copyRecBtn.className = "btn btn-sm";
        copyRecBtn.style.alignSelf = "flex-start";
        copyRecBtn.textContent = "Copy record (JSON)";
        copyRecBtn.addEventListener("click", () => {
          copyTextWithFeedback(copyRecBtn, JSON.stringify(r, null, 2), "Copy record (JSON)");
        });
        body.appendChild(copyRecBtn);

        recDet.appendChild(body);
        det.appendChild(recDet);
      });

      container.appendChild(det);
    });
  }

  function renderGpsState() {
    const gps = state.gpsResult;
    const badge = $("gps-badge");
    const clearBtn = $("clear-gps-btn");
    const out = $("gps-output");
    out.innerHTML = "";
    if (!gps) {
      const gpsDetected = Boolean(state.inspection && state.inspection.inventory && state.inspection.inventory.gps_present_indicator);
      badge.textContent = gpsDetected ? "Detected · Hidden" : "Hidden";
      clearBtn.classList.add("hidden");
      out.textContent = "GPS values have not been read for display.";
      return;
    }
    badge.textContent = gps.gps_state || gps.status;
    clearBtn.classList.remove("hidden");
    if (gps.status === "Present" && typeof gps.latitude === "number" && typeof gps.longitude === "number") {
      const coordLine = document.createElement("div");
      coordLine.className = "mono tabular";
      coordLine.style.color = "#FFFFFF";
      coordLine.textContent = `Latitude: ${gps.latitude.toFixed(6)} · Longitude: ${gps.longitude.toFixed(6)}` +
        (typeof gps.altitude_meters === "number" ? ` · Altitude: ${gps.altitude_meters.toFixed(1)} m` : "") +
        (gps.timestamp_utc ? ` · Timestamp: ${gps.timestamp_utc}` : "");
      out.appendChild(coordLine);
    } else {
      const noteLine = document.createElement("div");
      noteLine.textContent = gps.note || "No GPS coordinates were found in this image.";
      out.appendChild(noteLine);
    }

    const extraEntries = gps.extra_properties ? Object.entries(gps.extra_properties) : [];
    if (extraEntries.length) {
      const extraLine = document.createElement("div");
      extraLine.className = "small-copy";
      extraLine.style.marginTop = "6px";
      extraLine.textContent = "Additional GPS properties: " + extraEntries.map(([k, v]) => `${k}=${v}`).join(" · ");
      out.appendChild(extraLine);
    }

    const rawEntries = gps.raw_tags ? Object.entries(gps.raw_tags) : [];
    if (rawEntries.length) {
      const rawBox = document.createElement("div");
      rawBox.className = "small-copy mono";
      rawBox.style.marginTop = "6px";
      rawBox.textContent = "Raw EXIF GPS tags: " + rawEntries.map(([k, v]) => `${k}=${v}`).join(" | ");
      out.appendChild(rawBox);
    }
  }

  function renderElaScreen() {
    const data = state.inspection;
    $("ela-empty").classList.toggle("hidden", Boolean(data));
    $("ela-content").classList.toggle("hidden", !data);
    if (!data) return;

    const isJpeg = data.properties.image_format === "JPEG";
    const nonJpeg = $("ela-non-jpeg");
    nonJpeg.classList.toggle("hidden", isJpeg);
    $("ela-controls").classList.toggle("hidden", !isJpeg);
    if (!isJpeg) {
      nonJpeg.textContent = `ELA applies to JPEG images only. This file is ${data.properties.image_format}; ELA was not run.`;
      $("ela-results").classList.add("hidden");
      return;
    }

    const ela = state.elaResult;
    $("ela-results").classList.toggle("hidden", !ela);
    if (!ela) return;

    $("ela-proc-badge").textContent = `PROCESSED · Q${ela.quality} ×${ela.error_scale}`;
    $("ela-res-img").src = "data:image/png;base64," + ela.residual_png_base64;
    $("ela-mean").textContent = ela.mean_absolute_difference.toFixed(3);
    $("ela-pct").textContent = ela.changed_pixel_percent.toFixed(1) + "%";
    $("ela-max").textContent = String(ela.maximum_channel_difference);
    $("ela-method").textContent = ela.method;
    $("ela-limitations").textContent = ela.limitations;
  }

  function buildHistogramSvg(series, height, showAxes) {
    const w = 800;
    const padL = showAxes ? 44 : 8;
    const padR = 12;
    const padT = 12;
    const padB = showAxes ? 26 : 8;
    const plotW = w - padL - padR;
    const plotH = height - padT - padB;
    const maxVal = Math.max(1, ...series.flatMap((s) => s.counts));

    let lines = "";
    for (let g = 0; g <= 4; g++) {
      const y = padT + (plotH * g) / 4;
      lines += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="#303030" stroke-width="1"/>`;
    }
    if (showAxes) {
      [0, 64, 128, 192, 255].forEach((tick) => {
        const x = padL + (tick / 255) * plotW;
        lines += `<text x="${x}" y="${height - 6}" fill="#B3B3B3" font-size="11" text-anchor="middle" font-family="monospace">${tick}</text>`;
      });
    }
    series.forEach((s) => {
      const pts = s.counts
        .map((c, idx) => {
          const x = (padL + (idx / 255) * plotW).toFixed(1);
          const y = (padT + plotH - (c / maxVal) * plotH).toFixed(1);
          return `${x},${y}`;
        })
        .join(" ");
      const dash = s.dash ? ` stroke-dasharray="${s.dash}"` : "";
      lines += `<polyline fill="none" stroke="${s.color}" stroke-width="${s.width}"${dash} points="${pts}"/>`;
    });
    return `<svg viewBox="0 0 ${w} ${height}" class="svg-chart" role="img">${lines}</svg>`;
  }

  function renderHistogramScreen() {
    const data = state.inspection;
    $("run-hist-btn").disabled = !data;
    $("hist-empty").classList.toggle("hidden", Boolean(data));
    const h = state.histResult;
    $("hist-results").classList.toggle("hidden", !h);
    if (!h) return;

    $("hist-meta").textContent = `${h.width} × ${h.height} px · ${h.frame_count} frame(s) · ${h.pixel_count.toLocaleString()} decoded pixels`;
    $("hist-combined-svg").innerHTML = buildHistogramSvg(
      [
        { counts: h.combined, color: "#FFFFFF", width: 2, dash: "" },
        { counts: h.red, color: "#B3B3B3", width: 1.5, dash: "5 3" },
        { counts: h.green, color: "#B3B3B3", width: 1.5, dash: "2 3" },
        { counts: h.blue, color: "#777777", width: 1.5, dash: "7 3 2 3" },
      ],
      220,
      true
    );
    $("hist-r-svg").innerHTML = buildHistogramSvg([{ counts: h.red, color: "#FFFFFF", width: 1.8, dash: "" }], 110, false);
    $("hist-g-svg").innerHTML = buildHistogramSvg([{ counts: h.green, color: "#B3B3B3", width: 1.8, dash: "4 2" }], 110, false);
    $("hist-b-svg").innerHTML = buildHistogramSvg([{ counts: h.blue, color: "#777777", width: 1.8, dash: "2 2" }], 110, false);
    $("hist-limitations").textContent = h.limitations;
  }

  function renderReportsScreen() {
    const data = state.inspection;
    $("fr-empty").classList.toggle("hidden", Boolean(data));
    $("fr-content").classList.toggle("hidden", !data);
    if (!data) return;

    $("rpt-inc-ela").disabled = !state.elaResult;
    if (!state.elaResult) $("rpt-inc-ela").checked = false;
    $("rpt-inc-hist").disabled = !state.histResult;
    if (!state.histResult) $("rpt-inc-hist").checked = false;

    const gpsReady = Boolean(state.gpsResult && state.gpsResult.status === "Present");
    const excludeGpsEl = $("rpt-exclude-gps");
    if (!gpsReady) {
      excludeGpsEl.checked = true;
      excludeGpsEl.disabled = true;
    } else {
      excludeGpsEl.disabled = false;
    }

    const includeGps = gpsReady && !excludeGpsEl.checked;
    $("rpt-gps-notice").textContent = includeGps
      ? "GPS coordinates will be included in the exported PDF by explicit selection."
      : "GPS exclusion active: Location coordinates will be omitted from the exported PDF.";

    const sections = [];
    if ($("rpt-inc-assess").checked) sections.push("Assessment");
    if ($("rpt-inc-props").checked) sections.push("Properties");
    if ($("rpt-inc-meta").checked) sections.push("Metadata");
    if ($("rpt-inc-ela").checked) sections.push("ELA");
    if ($("rpt-inc-hist").checked) sections.push("Histogram");
    if ($("rpt-inc-malware").checked) sections.push("Malware & Security");

    $("pv-filename").textContent = data.properties.filename;
    $("pv-dims").textContent = `${data.properties.width} × ${data.properties.height} px (${data.properties.image_format})`;
    $("pv-outcome").textContent = data.assessment.outcome;
    $("pv-hash").textContent = data.sha256;
    $("pv-sections").textContent = sections.join(", ") || "None";
    $("pv-gps").textContent = includeGps ? "Included by explicit user selection" : "Excluded by default";
    $("pv-paths").textContent = $("rpt-redact-paths").checked ? "Enabled (basename only)" : "Disabled";

    $("rpt-download-link").classList.add("hidden");
    $("rpt-meta-caption").textContent = "";
  }

  async function handleMainUpload(file) {
    if (!file) return;
    const errEl = $("upload-error");
    const statusEl = $("upload-status");
    const browseBtn = $("browse-btn");
    const dropZoneEl = $("drop-zone");

    errEl.classList.add("hidden");
    errEl.textContent = "";
    statusEl.textContent = `Inspecting "${file.name}" locally (including malware scan)...`;
    statusEl.classList.remove("hidden");
    browseBtn.disabled = true;
    dropZoneEl.setAttribute("aria-busy", "true");

    try {
      const resp = await fetch("/api/inspect", {
        method: "POST",
        headers: apiHeaders({ "X-Filename": encodeURIComponent(file.name) }),
        body: file,
      });
      let json = null;
      try {
        json = await resp.json();
      } catch (_) {
        json = null;
      }
      if (!resp.ok || !json) {
        statusEl.classList.add("hidden");
        errEl.textContent = (json && json.error) || `Upload failed (HTTP ${resp.status}).`;
        errEl.classList.remove("hidden");
        return;
      }
      if (state.objectUrl) URL.revokeObjectURL(state.objectUrl);
      state.objectUrl = URL.createObjectURL(file);
      state.sessionId = json.session_id;
      state.inspection = json;
      state.gpsResult = null;
      if ($("gps-section")) $("gps-section").removeAttribute("open");
      state.elaResult = null;
      state.histResult = null;
      $("meta-export-status").className = "notice-bar hidden";
      $("meta-export-status").textContent = "";

      updateStatusPills();
      renderRecent(json.recent_records || []);
      renderImageAnalysis();
      renderMetadataAndAssessment();
      renderElaScreen();
      renderHistogramScreen();
      renderReportsScreen();

      const p = json.properties;
      statusEl.textContent = `Loaded "${p.filename}" (${p.width} × ${p.height} px, ${p.image_format}). Use the sidebar or module cards to inspect.`;
      statusEl.classList.remove("hidden");
    } catch (err) {
      statusEl.classList.add("hidden");
      errEl.textContent = (err && err.message) ? `Upload failed: ${err.message}` : "Upload failed due to a local connection or processing error.";
      errEl.classList.remove("hidden");
    } finally {
      browseBtn.disabled = false;
      dropZoneEl.removeAttribute("aria-busy");
    }
  }

  // Upload events
  $("browse-btn").addEventListener("click", (e) => {
    e.stopPropagation();
    $("file-input").click();
  });
  $("file-input").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (file) handleMainUpload(file);
  });

  const dropZone = $("drop-zone");
  dropZone.addEventListener("click", (e) => {
    if (e.target.closest("button") || e.target.closest("input")) return;
    $("file-input").click();
  });
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleMainUpload(e.dataTransfer.files[0]);
    }
  });

  // Copy SHA-256
  $("copy-hash-btn").addEventListener("click", () => {
    const text = $("sha256-value").textContent.trim();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    $("copy-hash-btn").textContent = "Copied";
    setTimeout(() => { $("copy-hash-btn").textContent = "Copy SHA-256"; }, 1500);
  });

  // Expand / collapse / copy all non-GPS metadata & filter listeners
  $("expand-all-btn").addEventListener("click", () => {
    document.querySelectorAll("details.meta-group:not(#gps-section)").forEach((d) => {
      d.setAttribute("open", "");
      d.querySelectorAll("details.meta-record").forEach((rec) => rec.setAttribute("open", ""));
    });
  });
  $("collapse-all-btn").addEventListener("click", () => {
    document.querySelectorAll("details.meta-group, details.meta-record").forEach((d) => {
      d.removeAttribute("open");
    });
  });
  $("copy-all-meta-btn").addEventListener("click", () => {
    const filtered = getFilteredRecords();
    copyTextWithFeedback($("copy-all-meta-btn"), JSON.stringify(filtered, null, 2), "Copy all non-GPS");
  });

  async function exportMetadataFile(format) {
    const statusEl = $("meta-export-status");
    statusEl.className = "notice-bar hidden";
    statusEl.textContent = "";
    try {
      const resp = await fetch(`/api/metadata/export?format=${encodeURIComponent(format)}`, {
        method: "GET",
        headers: apiHeaders(),
      });
      if (!resp.ok) {
        let errMsg = `Metadata ${format.toUpperCase()} export failed.`;
        try {
          const errJson = await resp.json();
          if (errJson && errJson.error) errMsg = errJson.error;
        } catch (_) {}
        statusEl.className = "notice-bar error";
        statusEl.textContent = errMsg;
        return;
      }
      const blob = await resp.blob();
      const disp = resp.headers.get("Content-Disposition") || "";
      const m = /filename="([^"]+)"/.exec(disp);
      const fname = m ? m[1] : `pixeltruth_metadata.${format}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fname;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      statusEl.className = "notice-bar";
      statusEl.textContent = `Exported non-GPS metadata inventory as ${format.toUpperCase()} (${fname}).`;
    } catch (_) {
      statusEl.className = "notice-bar error";
      statusEl.textContent = `Metadata ${format.toUpperCase()} export failed due to a local connection error.`;
    }
  }
  $("export-json-btn").addEventListener("click", () => exportMetadataFile("json"));
  $("export-csv-btn").addEventListener("click", () => exportMetadataFile("csv"));
  ["meta-search", "meta-filter-source", "meta-filter-category", "meta-filter-type", "meta-filter-status"].forEach((id) => {
    $(id).addEventListener("input", renderMetadataGroups);
    $(id).addEventListener("change", renderMetadataGroups);
  });
  $("meta-reset-filters-btn").addEventListener("click", () => {
    $("meta-search").value = "";
    $("meta-filter-source").value = "";
    $("meta-filter-category").value = "";
    $("meta-filter-type").value = "";
    $("meta-filter-status").value = "";
    renderMetadataGroups();
  });

  // GPS reveal / clear
  $("reveal-gps-btn").addEventListener("click", async () => {
    const btn = $("reveal-gps-btn");
    const out = $("gps-output");
    btn.disabled = true;
    out.textContent = "Reading GPS metadata...";
    try {
      const resp = await fetch("/api/gps/reveal", { method: "POST", headers: apiHeaders() });
      let json = null;
      try {
        json = await resp.json();
      } catch (_) {
        json = null;
      }
      if (!resp.ok || !json) {
        out.textContent = (json && json.error) || `Unable to read GPS metadata (HTTP ${resp.status}).`;
        return;
      }
      state.gpsResult = json;
      renderGpsState();
      renderReportsScreen();
    } catch (err) {
      out.textContent = (err && err.message) ? `GPS lookup failed: ${err.message}` : "GPS lookup failed due to a local connection error.";
    } finally {
      btn.disabled = false;
    }
  });
  $("clear-gps-btn").addEventListener("click", async () => {
    try {
      await fetch("/api/gps/clear", { method: "POST", headers: apiHeaders() });
    } catch (_) {}
    state.gpsResult = null;
    if ($("gps-section")) $("gps-section").removeAttribute("open");
    renderGpsState();
    renderReportsScreen();
  });

  // ELA sliders & run
  $("ela-quality").addEventListener("input", (e) => { $("ela-quality-val").textContent = e.target.value + "%"; });
  $("ela-scale").addEventListener("input", (e) => { $("ela-scale-val").textContent = e.target.value + "×"; });
  $("run-ela-btn").addEventListener("click", async () => {
    const resp = await fetch("/api/ela", {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        quality: Number($("ela-quality").value),
        error_scale: Number($("ela-scale").value),
      }),
    });
    const json = await resp.json();
    if (resp.ok) {
      state.elaResult = json;
      renderElaScreen();
      renderReportsScreen();
    }
  });

  // RGB Histogram run
  $("run-hist-btn").addEventListener("click", async () => {
    const resp = await fetch("/api/histogram", { method: "POST", headers: apiHeaders() });
    const json = await resp.json();
    if (resp.ok) {
      state.histResult = json;
      renderHistogramScreen();
      renderReportsScreen();
    }
  });

  // Image Comparison
  async function uploadCompareSlot(slot, file) {
    $("cmp-error").classList.add("hidden");
    try {
      const resp = await fetch(`/api/compare/slot?slot=${slot}`, {
        method: "POST",
        headers: apiHeaders({ "X-Filename": encodeURIComponent(file.name) }),
        body: file,
      });
      let json = null;
      try {
        json = await resp.json();
      } catch (_) {
        json = null;
      }
      if (!resp.ok || !json) {
        $("cmp-error").textContent = (json && json.error) || `Comparison upload failed (HTTP ${resp.status}).`;
        $("cmp-error").classList.remove("hidden");
        return;
      }
      state.sessionId = json.session_id;
      const url = URL.createObjectURL(file);
      if (slot === "a") {
        if (state.cmpAUrl) URL.revokeObjectURL(state.cmpAUrl);
        state.cmpAUrl = url;
        state.cmpAInfo = json;
      } else {
        if (state.cmpBUrl) URL.revokeObjectURL(state.cmpBUrl);
        state.cmpBUrl = url;
        state.cmpBInfo = json;
      }
      renderCompareSlots();
      if (state.cmpAInfo && state.cmpBInfo) await runCompare();
    } catch (err) {
      $("cmp-error").textContent = (err && err.message) ? `Comparison upload failed: ${err.message}` : "Comparison upload failed.";
      $("cmp-error").classList.remove("hidden");
    }
  }

  function renderCompareSlots() {
    [["a", state.cmpAInfo, state.cmpAUrl], ["b", state.cmpBInfo, state.cmpBUrl]].forEach(([s, info, url]) => {
      $(`cmp-${s}-name`).textContent = info ? info.filename : "Not selected";
      $(`cmp-${s}-dims`).textContent = info ? info.dimensions : "—";
      $(`cmp-${s}-size`).textContent = info ? (info.file_size_bytes / 1024).toFixed(1) + " KB" : "—";
      $(`cmp-${s}-hash`).textContent = info ? info.sha256 : "—";
      $(`cmp-${s}-img`).classList.toggle("hidden", !url);
      $(`cmp-${s}-placeholder`).classList.toggle("hidden", Boolean(url));
      if (url) $(`cmp-${s}-img`).src = url;
    });
    $("cmp-status-pill").textContent = (state.cmpAInfo && state.cmpBInfo)
      ? "Pair: A vs B Loaded"
      : "Pair: Select two images";
  }

  async function runCompare() {
    const resp = await fetch("/api/compare", { method: "POST", headers: apiHeaders() });
    const json = await resp.json();
    if (!resp.ok) {
      $("cmp-error").textContent = json.error || "Comparison failed.";
      $("cmp-error").classList.remove("hidden");
      return;
    }
    $("cmp-results").classList.remove("hidden");
    const mBody = $("cmp-metrics-body");
    mBody.innerHTML = "";
    json.metrics.forEach((m) => {
      const tr = document.createElement("tr");
      [m.label, m.reference_value, m.suspect_value, m.matches ? "Match" : "Different"].forEach((v) => {
        const td = document.createElement("td");
        td.textContent = v;
        tr.appendChild(td);
      });
      mBody.appendChild(tr);
    });
    $("cmp-similarity").textContent = json.sampled_pixel_similarity !== null
      ? `Sampled pixel similarity indicator: ${json.sampled_pixel_similarity.toFixed(3)} — ${json.similarity_note}`
      : json.similarity_note;

    const dBody = $("cmp-meta-body");
    dBody.innerHTML = "";
    if (!json.metadata_differences.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.className = "muted";
      td.textContent = "No differences were found among the inspected metadata fields.";
      tr.appendChild(td);
      dBody.appendChild(tr);
    } else {
      json.metadata_differences.forEach((d) => {
        const tr = document.createElement("tr");
        [d.label, d.reference_value, d.suspect_value].forEach((v) => {
          const td = document.createElement("td");
          td.textContent = v;
          tr.appendChild(td);
        });
        dBody.appendChild(tr);
      });
    }
  }

  $("cmp-a-btn").addEventListener("click", () => $("cmp-a-input").click());
  $("cmp-b-btn").addEventListener("click", () => $("cmp-b-input").click());
  $("cmp-a-input").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0];
    e.target.value = "";
    if (f) uploadCompareSlot("a", f);
  });
  $("cmp-b-input").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0];
    e.target.value = "";
    if (f) uploadCompareSlot("b", f);
  });
  $("swap-ab-btn").addEventListener("click", async () => {
    if (!state.sessionId) return;
    await fetch("/api/compare/swap", { method: "POST", headers: apiHeaders() });
    [state.cmpAInfo, state.cmpBInfo] = [state.cmpBInfo, state.cmpAInfo];
    [state.cmpAUrl, state.cmpBUrl] = [state.cmpBUrl, state.cmpAUrl];
    renderCompareSlots();
    if (state.cmpAInfo && state.cmpBInfo) await runCompare();
  });

  // Forensic Reports live preview & PDF generation
  ["rpt-inc-assess", "rpt-inc-props", "rpt-inc-meta", "rpt-inc-ela", "rpt-inc-hist", "rpt-inc-malware", "rpt-exclude-gps", "rpt-redact-paths"].forEach((id) => {
    $(id).addEventListener("change", renderReportsScreen);
  });

  $("rpt-generate-btn").addEventListener("click", async () => {
    const gpsReady = Boolean(state.gpsResult && state.gpsResult.status === "Present");
    const includeGps = gpsReady && !$("rpt-exclude-gps").checked;
    const resp = await fetch("/api/report/generate", {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        include_assessment: $("rpt-inc-assess").checked,
        include_properties: $("rpt-inc-props").checked,
        include_metadata: $("rpt-inc-meta").checked,
        include_ela: $("rpt-inc-ela").checked,
        include_histogram: $("rpt-inc-hist").checked,
        include_malware_scan: $("rpt-inc-malware").checked,
        include_gps: includeGps,
        redact_local_paths: $("rpt-redact-paths").checked,
      }),
    });
    const json = await resp.json();
    if (resp.ok) {
      const dl = $("rpt-download-link");
      dl.href = `/api/report/download?token=${encodeURIComponent(json.download_token)}&session=${encodeURIComponent(state.sessionId)}`;
      dl.classList.remove("hidden");
      $("rpt-meta-caption").textContent = `Report ID: ${json.report_id} · Generated: ${json.generated_at_utc}`;
      dl.click();
    }
  });
})();
