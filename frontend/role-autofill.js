document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.application-form').forEach((form) => {
    const companySelect = form.querySelector('[name="companyId"]');
    const roleInput = form.querySelector('[name="role"]');
    const roleMessage = form.querySelector('.role-load-message');
    const applicationPicker = form.querySelector('[data-application-picker]');
    let requestSequence = 0;

    const loadRole = async (companyId) => {
      const requestId = ++requestSequence;
      roleInput.value = '';

      if (!companyId) {
        roleMessage.textContent = 'Select a company to load its role.';
        return;
      }

      roleMessage.textContent = 'Loading role...';
      try {
        const response = await fetch(`/api/companies/${encodeURIComponent(companyId)}`, {
          headers: { Accept: 'application/json' },
          credentials: 'same-origin'
        });
        let company;
        try {
          company = await response.json();
        } catch {
          throw new Error('Unable to read company details from the server.');
        }
        if (!response.ok) {
          throw new Error(company.error || 'Unable to load company details.');
        }
        if (requestId !== requestSequence || companySelect.value !== companyId) {
          return;
        }

        const role = typeof company.role_offered === 'string' ? company.role_offered.trim() : '';
        if (!role) {
          roleMessage.textContent = 'No role is listed for this company.';
          return;
        }
        roleInput.value = role;
        roleMessage.textContent = 'Role loaded. You can edit it if needed.';
      } catch (error) {
        if (requestId !== requestSequence || companySelect.value !== companyId) {
          return;
        }
        roleInput.value = '';
        roleMessage.textContent = error instanceof Error
          ? `${error.message} Select the company again to retry.`
          : 'Unable to load company role. Select the company again to retry.';
      }
    };

    companySelect.addEventListener('change', () => loadRole(companySelect.value));

    if (applicationPicker) {
      applicationPicker.addEventListener('change', () => {
        const selectedApplication = applicationPicker.selectedOptions[0];
        requestSequence++;
        if (!applicationPicker.value || !selectedApplication) {
          companySelect.value = '';
          roleInput.value = '';
          form.querySelector('[name="type"]').value = '';
          form.querySelector('[name="appliedDate"]').value = '';
          form.querySelector('[name="status"]').value = '';
          form.querySelector('[name="followUpDate"]').value = '';
          roleMessage.textContent = '';
          return;
        }

        companySelect.value = selectedApplication.dataset.companyId || '';
        roleInput.value = selectedApplication.dataset.role || '';
        form.querySelector('[name="type"]').value = selectedApplication.dataset.type || '';
        form.querySelector('[name="appliedDate"]').value = selectedApplication.dataset.appliedDate || '';
        form.querySelector('[name="status"]').value = selectedApplication.dataset.status || '';
        form.querySelector('[name="followUpDate"]').value = selectedApplication.dataset.followUpDate || '';
        roleMessage.textContent = roleInput.value
          ? 'Loaded the saved role. Changing the company will load its listed role.'
          : '';

        if (!roleInput.value && companySelect.value) {
          loadRole(companySelect.value);
        }
      });
    }
  });
});
