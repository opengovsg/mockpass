document.addEventListener('DOMContentLoaded', () => {
  const tableBody = document.getElementById('personas-tbody');
  const loadingInd = document.getElementById('loading-indicator');
  const emptyState = document.getElementById('empty-state');
  const btnRefresh = document.getElementById('btn-refresh');
  const form = document.getElementById('persona-form');
  const ageConfigSelect = document.getElementById('ageConfig');
  const dynamicAgeGroup = document.getElementById('dynamicAgeGroup');
  const fixedDobGroup = document.getElementById('fixedDobGroup');
  const saveStatus = document.getElementById('save-status');

  // Toggle age configuration inputs
  ageConfigSelect.addEventListener('change', (e) => {
    if (e.target.value === 'dynamic') {
      dynamicAgeGroup.classList.remove('hidden');
      fixedDobGroup.classList.add('hidden');
    } else {
      dynamicAgeGroup.classList.add('hidden');
      fixedDobGroup.classList.remove('hidden');
    }
  });

  // Load personas from backend
  const loadPersonas = async () => {
    tableBody.innerHTML = '';
    loadingInd.classList.remove('hidden');
    emptyState.classList.add('hidden');
    
    try {
      const res = await fetch('/admin/api/personas');
      if (!res.ok) throw new Error('Failed to fetch personas');
      const data = await res.json();
      
      loadingInd.classList.add('hidden');
      
      const keys = Object.keys(data);
      if (keys.length === 0) {
        emptyState.classList.remove('hidden');
        return;
      }
      
      keys.forEach(nric => {
        const p = data[nric];
        const tr = document.createElement('tr');
        
        let ageText = p.dynamic_age !== undefined ? `Dynamic: ${p.dynamic_age} years` : `Fixed: ${p.dob ? p.dob.value : 'N/A'}`;
        let incomeL = p.householdincome && p.householdincome.low ? p.householdincome.low.value : 0;
        let incomeH = p.householdincome && p.householdincome.high ? p.householdincome.high.value : 0;
        
        tr.innerHTML = `
          <td><strong>${nric}</strong></td>
          <td>${p.name ? p.name.value : 'N/A'}</td>
          <td>${p.nationality ? p.nationality.code : 'N/A'}</td>
          <td>${ageText}</td>
          <td>$${incomeL} - $${incomeH}</td>
        `;
        tableBody.appendChild(tr);
      });
    } catch (err) {
      console.error(err);
      loadingInd.innerHTML = 'Error loading data. Is the server running?';
    }
  };

  btnRefresh.addEventListener('click', loadPersonas);

  // Handle form submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    saveStatus.textContent = 'Saving...';
    saveStatus.className = 'status-msg';

    const formData = new FormData(form);
    const payload = {
      nric: formData.get('nric'),
      name: formData.get('name'),
      nationality: formData.get('nationality'),
      incomeLow: parseInt(formData.get('incomeLow'), 10),
      incomeHigh: parseInt(formData.get('incomeHigh'), 10),
      schoolName: formData.get('schoolName'),
      eduLevel: formData.get('eduLevel'),
      maritalStatus: formData.get('maritalStatus'),
      noOfChildren: parseInt(formData.get('noOfChildren'), 10) || 0,
      regAdd: formData.get('regAdd'),
      mobileNo: formData.get('mobileNo'),
      email: formData.get('email'),
      password: formData.get('password') || crypto.randomUUID()
    };

    if (formData.get('ageConfig') === 'dynamic') {
      payload.dynamic_age = parseInt(formData.get('dynamicAge'), 10);
    } else {
      payload.dob = formData.get('fixedDob');
    }

    try {
      const res = await fetch('/admin/api/personas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to save');
      }

      saveStatus.textContent = 'Persona saved successfully!';
      saveStatus.className = 'status-msg success';
      
      // Clear form except NRIC prefix
      form.reset();
      
      setTimeout(() => {
        saveStatus.textContent = '';
      }, 3000);
      
      loadPersonas();
    } catch (err) {
      console.error(err);
      saveStatus.textContent = err.message;
      saveStatus.className = 'status-msg error';
    }
  });

  // Initial load
  loadPersonas();
});
