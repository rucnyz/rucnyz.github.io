---
layout: page
permalink: /publications/
title: publications
description: (*) denotes equal contribution
years: [2025, 2024,2023,2022]
nav: true
nav_order: 1
---
<!-- _pages/publications.md -->
<div class="publications">

{%- for y in page.years %}
  <h2 class="year">{{y}}</h2>
  {% bibliography -f papers -q @*[year={{y}}]* %}
{% endfor %}

</div>
