import RuleForm from '../components/rules/RuleForm'
import RuleTable from '../components/rules/RuleTable'

function RulesPage({
  rules,
  loading,
  form,
  showAdvanced,
  setShowAdvanced,
  submitting,
  handleChange,
  handleAddRule,
  handleDeleteRule,
  resetForm,
}) {
  return (
    <>
      <div className="page-header">
        <h2>방화벽 룰 확인 / 추가</h2>
        <p>자동 생성 규칙을 조회하고 새 규칙을 추가하거나 삭제합니다.</p>
      </div>

      <div className="main-grid">
        <RuleForm
          form={form}
          showAdvanced={showAdvanced}
          setShowAdvanced={setShowAdvanced}
          submitting={submitting}
          handleChange={handleChange}
          handleAddRule={handleAddRule}
          resetForm={resetForm}
        />

        <RuleTable
          rules={rules}
          loading={loading}
          handleDeleteRule={handleDeleteRule}
        />
      </div>
    </>
  )
}

export default RulesPage
