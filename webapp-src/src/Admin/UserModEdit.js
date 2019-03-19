import React, { Component } from 'react';

class UserModEdit extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      mod: props.mod,
      modTypes: props.modTypes,
      add: props.add,
      callback: props.callback
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeName = this.changeName.bind(this);
    this.changeDisplayName = this.changeDisplayName.bind(this);
    this.changeType = this.changeType.bind(this);
    this.toggleReadonly = this.toggleReadonly.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      mod: nextProps.mod,
      modTypes: nextProps.modTypes,
      add: nextProps.add,
      callback: nextProps.callback
    });
  }

  closeModal(e, result) {
  }
  
  changeName(e) {
    var mod = this.state.mod;
    mod.name = e.target.value;
    this.setState({mod: mod});
  }
  
  changeDisplayName(e) {
    var mod = this.state.mod;
    mod.display_name = e.target.value;
    this.setState({mod: mod});
  }
  
  changeType(e) {
    var mod = this.state.mod;
    mod.module = e.target.value;
    this.setState({mod: mod});
  }
  
  toggleReadonly(e) {
    var mod = this.state.mod;
    mod.readonly = !mod.readonly;
    this.setState({mod: mod});
  }
  
	render() {
		return (
    <div className="modal fade" id="editUserModModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
      <div className="modal-dialog" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="confirmModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            <form className="needs-validation" noValidate>
              <div className="form-group">
                <label htmlFor="scope-name">{i18next.t("admin.scope-name")}</label>
                <input type="text" className="form-control" id="scope-name" placeholder={i18next.t("admin.scope-name-ph")} maxLength="128" value={this.state.scope.name} onChange={(e) => this.changeName(e)} disabled={!this.state.add} />
              </div>
              <div className="form-group">
                <label htmlFor="scope-display-name">{i18next.t("admin.scope-display-name")}</label>
                <input type="text" className="form-control" id="scope-display-name" placeholder={i18next.t("admin.scope-display-name-ph")} maxLength="256" value={this.state.scope.display_name} onChange={(e) => this.changeDisplayName(e)}/>
              </div>
              <div className="form-group">
                <label htmlFor="scope-description">{i18next.t("admin.scope-description")}</label>
                <input type="text" className="form-control" id="scope-description" placeholder={i18next.t("admin.scope-description-ph")} maxLength="512" value={this.state.scope.description} onChange={(e) => this.changeDescription(e)}/>
              </div>
              <hr/>
              <div className="form-group">
                <h4>{i18next.t("admin.scope-auth-schemes-title")}</h4>
              </div>
              <div className="form-group">
                <label htmlFor="scope-scheme-password">{i18next.t("admin.scope-scheme-password")}</label>
                <input type="checkbox" className="form-control" id="scope-scheme-password" onChange={(e) => this.togglePasswordRequired(e)} checked={this.state.scope.password_required} />
              </div>
              <div className="form-group">
                {groupList}
                {modSchemeDropdown}
              </div>
            </form>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
            <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default UserModEdit;
