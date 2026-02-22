// DOM Elements
const questionsGrid = document.getElementById('questionsGrid');
const categoryTabs = document.getElementById('categoryTabs');
const totalQuestionsEl = document.getElementById('totalQuestions');

let allQuestions = [];
let categories = new Set();
let currentCategory = 'all';

// Fetch daily data
async function loadData() {
  try {
    const response = await fetch('data.json');
    const data = await response.json();
    
    allQuestions = data.questions || [];
    totalQuestionsEl.textContent = allQuestions.length;
    
    // Extract unique categories
    allQuestions.forEach(q => categories.add(q.category));
    
    renderTabs();
    renderQuestions();
  } catch (error) {
    console.error('Failed to load interview data:', error);
    questionsGrid.innerHTML = `
      <div style="text-align:center; padding: 4rem; color: var(--accent-warning);">
        <h3>No Daily Feed Found</h3>
        <p style="margin-top: 1rem; color: var(--text-muted)">The OpenClaw interview-prep agent has not published today's feed yet. Check back later.</p>
      </div>
    `;
  }
}

// Render Category Filters
function renderTabs() {
  // We already have 'All Topics' in HTML, just append others
  categories.forEach(cat => {
    const btn = document.createElement('button');
    btn.className = 'tab-btn';
    btn.textContent = cat;
    btn.dataset.category = cat;
    btn.addEventListener('click', () => filterByCategory(cat));
    categoryTabs.appendChild(btn);
  });
  
  // Attach event to the default 'All' button
  document.querySelector('.tab-btn[data-category="all"]').addEventListener('click', () => filterByCategory('all'));
}

// Handle Filtering
function filterByCategory(category) {
  currentCategory = category;
  
  // Update UI active states
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.category === category);
  });
  
  renderQuestions();
}

// Render Questions Accordion
function renderQuestions() {
  questionsGrid.innerHTML = '';
  
  const filtered = currentCategory === 'all' 
    ? allQuestions 
    : allQuestions.filter(q => q.category === currentCategory);
    
  if (filtered.length === 0) {return;}
  
  filtered.forEach((q, index) => {
    const card = document.createElement('div');
    card.className = 'question-card';
    card.style.animationDelay = `${index * 0.05}s`;
    
    // Format paragraph text (handle basic newlines if present)
    const answerFormatted = q.answer.replace(/\n\n/g, '<br><br>');
    
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title-area">
          <span class="category-tag">${q.category}</span>
          <h3 class="question-text">${q.question}</h3>
        </div>
        <div class="expand-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>
      </div>
      <div class="card-body">
        <div class="card-body-inner">
          ${answerFormatted}
        </div>
      </div>
    `;
    
    // Accordion Logic
    const header = card.querySelector('.card-header');
    const body = card.querySelector('.card-body');
    
    header.addEventListener('click', () => {
      const isOpen = card.classList.contains('open');
      
      // Close all others
      document.querySelectorAll('.question-card').forEach(c => {
        c.classList.remove('open');
        c.querySelector('.card-body').style.maxHeight = null;
      });
      
      // Toggle current
      if (!isOpen) {
        card.classList.add('open');
        const innerHeight = body.querySelector('.card-body-inner').offsetHeight;
        body.style.maxHeight = `${innerHeight + 40}px`; // padding buffer
      }
    });
    
    questionsGrid.appendChild(card);
  });
}

// Init
document.addEventListener('DOMContentLoaded', loadData);
