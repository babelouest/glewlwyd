import React, { Component } from 'react';

class ScopeEdit extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      scope: props.scope,
      add: props.add,
      modSchemes: props.modSchemes,
      cb: props.cb
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeName = this.changeName.bind(this);
    this.changeDisplayName = this.changeDisplayName.bind(this);
    this.changeDescription = this.changeDescription.bind(this);
    this.togglePasswordRequired = this.togglePasswordRequired.bind(this);
    this.addScheme = this.addScheme.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      scope: nextProps.scope,
      add: nextProps.add,
      modSchemes: nextProps.modSchemes,
      cb: nextProps.cb
    });
  }

  closeModal(e, result) {
    if (this.state.cb) {
    }
  }
  
  changeName(e) {
    var scope = this.state.scope;
    scope.name = e.target.value;
    this.setState({scope: scope});
  }
  
  changeDisplayName(e) {
    var scope = this.state.scope;
    scope.display_name = e.target.value;
    this.setState({scope: scope});
  }
  
  changeDescription(e) {
    var scope = this.state.scope;
    scope.description = e.target.value;
    this.setState({scope: scope});
  }
  
  togglePasswordRequired(e) {
    var scope = this.state.scope;
    scope.password_required = !scope.password_required;
    this.setState({scope: scope});
  }
  
  addScheme(scheme_name, group) {
    var scope = this.state.scope;
    if (!group) {
      // Add new group
      var i = 0;
      for (var key in scope.scheme) {
        i++;
      }
      group = "" + i;
    }
    var newScheme = {scheme_name: scheme_name}
    this.state.modSchemes.forEach((modScheme) => {
      if (modScheme.scheme_name === scheme_name) {
        newScheme.scheme_type = modScheme.scheme_type;
        newScheme.scheme_display_name = modScheme.scheme_display_name;
      }
    });
    scope.scheme[group].push(newScheme);
    this.setState({scope: scope});
  }

	render() {
    var groupList = [];
    var i = 0;
    var modSchemeListName = [];
    var modSchemeListDisplayName = [];
    var modSchemeListJsx;
    var modSchemeDropdown;
    // Create list of schemes
    this.state.modSchemes.forEach((scheme) => {
      if (scheme.enabled) {
        modSchemeListName.push(scheme.name);
        modSchemeListDisplayName.push(scheme.display_name);
      }
    });
    // Remove schemes that are already in the current scope
    for (var groupName in this.state.scope.scheme) {
      this.state.scope.scheme[groupName].forEach((scheme, index) => {
        if (modSchemeListName.indexOf(scheme.scheme_name) >= 0) {
          modSchemeListDisplayName.splice(modSchemeListName.indexOf(scheme.scheme_name), 1);
          modSchemeListName.splice(modSchemeListName.indexOf(scheme.scheme_name), 1);
        }
      });
    }
    // Build groups and scheme lists
    for (var groupName in this.state.scope.scheme) {
      var schemeList = [];
      var iScheme = 0;
      this.state.scope.scheme[groupName].forEach((scheme, index) => {
        var maxUse = "";
        // Add badge or
        if (schemeList.length) {
          schemeList.push(<span className="badge badge-secondary btn-icon-right" key={iScheme++}>{i18next.t("admin.or")}</span>);
        }
        // Add scheme
        schemeList.push(<span className="badge badge-primary btn-icon-right" key={iScheme++}>{scheme.scheme_display_name}{maxUse}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span>);
      });
      // Add badge and
      if (groupList.length) {
        groupList.push(<span className="badge badge-secondary btn-icon-right" key={i++}>{i18next.t("admin.and")}</span>);
      }
      if (modSchemeListName.length) {
        if (schemeList.length) {
          schemeList.push(<span className="badge badge-secondary btn-icon-right" key={iScheme++}>{i18next.t("admin.or")}</span>);
        }
        modSchemeListJsx = [];
        modSchemeListName.forEach((name, index) => {
          modSchemeListJsx.push(<a className="dropdown-item" href="#" key={index} onClick={() => this.addScheme(name, groupName)}>{modSchemeListDisplayName[index]}</a>);
        });
        schemeList.push(
          <div className="dropdown" key={iScheme++}>
            <button className="btn btn-secondary btn-sm dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {i18next.t("admin.scope-add-scheme-group")}
            </button>
            <div className="dropdown-menu" aria-labelledby="dropdownMenuButton">
              {modSchemeListJsx}
            </div>
          </div>
        );
      }
      groupList.push(<div className="card" style={{width: 18 + 'rem'}} key={i++}>
        <div className="card-body">
          <h5 className="card-title">{groupName}</h5>
          {schemeList}
        </div>
      </div>);
    }
    if (modSchemeListName.length) {
      modSchemeListJsx = [];
      modSchemeListName.forEach((name, index) => {
        modSchemeListJsx.push(<a className="dropdown-item" href="#" key={index} onClick={() => this.addScheme(name, false)}>{modSchemeListDisplayName[index]}</a>);
      });
      modSchemeDropdown = <div className="dropdown">
        <button className="btn btn-secondary btn-sm dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          {i18next.t("admin.scope-add-scheme-group")}
        </button>
        <div className="dropdown-menu" aria-labelledby="dropdownMenuButton">
          {modSchemeListJsx}
        </div>
      </div>
    }
		return (
    <div className="modal fade" id="editScopeModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
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
                <input type="text" className="form-control" id="scope-name" placeholder={i18next.t("admin.scope-name-ph")} value={this.state.scope.name} onChange={(e) => this.changeName(e)} disabled={!this.state.add} />
              </div>
              <div className="form-group">
                <label htmlFor="scope-display-name">{i18next.t("admin.scope-display-name")}</label>
                <input type="text" className="form-control" id="scope-display-name" placeholder={i18next.t("admin.scope-display-name-ph")} value={this.state.scope.display_name} onChange={(e) => this.changeDisplayName(e)}/>
              </div>
              <div className="form-group">
                <label htmlFor="scope-description">{i18next.t("admin.scope-description")}</label>
                <input type="text" className="form-control" id="scope-description" placeholder={i18next.t("admin.scope-description-ph")} value={this.state.scope.description} onChange={(e) => this.changeDescription(e)}/>
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

export default ScopeEdit;
