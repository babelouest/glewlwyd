import React, { Component } from 'react';
import i18next from 'i18next';

class ScopeEdit extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      scope: props.scope,
      add: props.add,
      errorList: {},
      hasError: false,
      modSchemes: props.modSchemes,
      callback: props.callback
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeName = this.changeName.bind(this);
    this.changeDisplayName = this.changeDisplayName.bind(this);
    this.changeDescription = this.changeDescription.bind(this);
    this.changePwdMaxAge = this.changePwdMaxAge.bind(this);
    this.togglePasswordRequired = this.togglePasswordRequired.bind(this);
    this.addScheme = this.addScheme.bind(this);
    this.handleRemoveScheme = this.handleRemoveScheme.bind(this);
    this.handleSelectSchemeRequired = this.handleSelectSchemeRequired.bind(this);
    this.exportRecord = this.exportRecord.bind(this);
    this.importRecord = this.importRecord.bind(this);
    this.getImportScope = this.getImportScope.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      scope: nextProps.scope,
      add: nextProps.add,
      errorList: {},
      hasError: false,
      modSchemes: nextProps.modSchemes,
      callback: nextProps.callback
    });
  }

  closeModal(e, result) {
    var scope = this.state.scope;
    if (result) {
      if (this.state.callback) {
        if (scope.name) {
          if (!scope.display_name) {
            delete(scope.display_name);
          }
          if (!scope.description) {
            delete(scope.description);
          }
          this.state.callback(result, scope);
        } else {
          this.setState({errorList: {name: i18next.t("admin.scope-error-name")}, hasError: true});
        }
      }
    } else {
      this.state.callback(result);
    }
  }
  
  changeName(e) {
    var scope = this.state.scope;
    scope.name = e.target.value;
    this.setState({scope: scope});
  }
  
  changePwdMaxAge(e) {
    var scope = this.state.scope;
    scope.password_max_age = parseInt(e.target.value);
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
      while (scope.scheme[group] !== undefined) {
        i++;
        group = "" + i;
      }
      scope.scheme[group] = [];
      if (!scope.scheme_required) {
        scope.scheme_required = {};
      }
      scope.scheme_required[group] = 1;
    }
    var newScheme = {scheme_name: scheme_name}
    this.state.modSchemes.forEach((modScheme) => {
      if (modScheme.name === scheme_name) {
        newScheme.scheme_type = modScheme.module;
        newScheme.scheme_display_name = modScheme.display_name;
      }
    });
    scope.scheme[group].push(newScheme);
    this.setState({scope: scope});
  }
  
  handleRemoveScheme(e, group, scheme) {
    var scope = this.state.scope;
    if (scope.scheme[group]) {
      scope.scheme[group].forEach((curScheme, index) => {
        if (curScheme.scheme_name === scheme.scheme_name) {
          scope.scheme[group].splice(index, 1);
          if (scope.scheme_required[group] > scope.scheme[group].length) {
            scope.scheme_required[group] = scope.scheme[group].length;
          }
          if (!scope.scheme[group].length) {
            delete(scope.scheme[group]);
            delete(scope.scheme_required[group]);
          }
        }
      });
    }
    this.setState({scope: scope});
  }
  
  handleSelectSchemeRequired(e, group, number) {
    e.preventDefault();
    var scope = this.state.scope;
    if (!scope.scheme_required) {
      scope.scheme_required = {};
    }
    scope.scheme_required[group] = number;
    this.setState({scope: scope});
  }

  exportRecord() {
    var exported = Object.assign({}, this.state.scope);
    var $anchor = $("#scope-download");
    $anchor.attr("href", "data:application/octet-stream;base64,"+btoa(JSON.stringify(exported)));
    $anchor.attr("download", (exported.name)+".json");
    $anchor[0].click();
  }
  
  importRecord() {
    $("#scope-upload").click();
  }

  getImportScope(e) {
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      try {
        let imported = JSON.parse(ev2.target.result);
        if (!this.state.add) {
          if (this.state.scope.name) {
            imported.name = this.state.scope.name;
          }
        }
        this.setState({scope: imported});
      } catch (err) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.import-error")});
      }
    };
    fr.readAsText(file);
  }
  
	render() {
    var groupList = [];
    var i = 0;
    var modSchemeListName = [];
    var modSchemeListDisplayName = [];
    var modSchemeListJsx;
    var modSchemeDropdown;
    var schemeRequiredDropdown;
    var hasError;
    if (this.state.hasError) {
      hasError = <span className="error-input text-right">{i18next.t("admin.error-input")}</span>;
    }
    // Create list of schemes
    this.state.modSchemes.forEach((scheme) => {
      if (scheme.enabled) {
        modSchemeListName.push(scheme.name);
        modSchemeListDisplayName.push(scheme.display_name||scheme.name);
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
    $.each (this.state.scope.scheme, (groupName, scheme) => {
      var schemeList = [];
      schemeRequiredDropdown = [];
      var iScheme = 0;
      scheme.forEach((scheme, index) => {
        // Add badge or
        if (schemeList.length) {
          schemeList.push(<span className="badge badge-secondary btn-icon-right" key={iScheme++}>{i18next.t("admin.or")}</span>);
        }
        // Add scheme
        schemeList.push(<a href="#" key={iScheme++} onClick={(e) => this.handleRemoveScheme(e, groupName, scheme)}><span className="badge badge-primary btn-icon-right">{scheme.scheme_display_name||scheme.scheme_name}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
        if ((this.state.scope.scheme_required && this.state.scope.scheme_required[groupName] === (index+1)) || (!index && !this.state.scope.scheme_required)) {
          schemeRequiredDropdown.push(<a className="dropdown-item active" href="#" key={index} disabled={true}>{index+1}</a>);
        } else {
          schemeRequiredDropdown.push(<a className="dropdown-item" href="#" key={index} onClick={(e) => this.handleSelectSchemeRequired(e, groupName, (index+1))}>{index+1}</a>);
        }
      });
      // Add badge
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
              {i18next.t("admin.scope-add-scheme")}
            </button>
            <div className="dropdown-menu" aria-labelledby="dropdownMenuButton">
              {modSchemeListJsx}
            </div>
          </div>
        );
      }
      
      groupList.push(
      <div className="card glwd-group-card" key={i++}>
        <div className="card-body">
          {schemeList}
        </div>
        <div className="dropdown">
          <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
            {i18next.t("admin.scope-scheme-required-count", {number: (this.state.scope.scheme_required&&this.state.scope.scheme_required[groupName]?this.state.scope.scheme_required[groupName]:1)})}
          </button>
          <div className="dropdown-menu" aria-labelledby="dropdownMenuButton">
            {schemeRequiredDropdown}
          </div>
        </div>
      </div>);
    });
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
        <div className="modal-dialog modal-lg" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id="confirmModalLabel">{this.state.title}</h5>
              <div className="btn-group btn-icon-right" role="group">
                <button disabled={this.state.add} type="button" className="btn btn-secondary" onClick={this.exportRecord} title={i18next.t("admin.export")}>
                  <i className="fas fa-download"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={this.importRecord} title={i18next.t("admin.import")}>
                  <i className="fas fa-upload"></i>
                </button>
              </div>
              <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <form className="needs-validation" noValidate>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" className="input-group-text" htmlFor="scope-name">{i18next.t("admin.scope-name")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["name"]?"form-control is-invalid":"form-control"} id="scope-name" placeholder={i18next.t("admin.scope-name-ph")} maxLength="128" value={this.state.scope.name||""} onChange={(e) => this.changeName(e)} disabled={!this.state.add} />
                  </div>
                  {this.state.errorList["name"]?<span className="error-input">{this.state.errorList["name"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="scope-display-name">{i18next.t("admin.scope-display-name")}</label>
                    </div>
                    <input type="text" className="form-control" id="scope-display-name" placeholder={i18next.t("admin.scope-display-name-ph")} maxLength="256" value={this.state.scope.display_name||""} onChange={(e) => this.changeDisplayName(e)}/>
                  </div>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="scope-description">{i18next.t("admin.scope-description")}</label>
                    </div>
                    <input type="text" className="form-control" id="scope-description" placeholder={i18next.t("admin.scope-description-ph")} maxLength="512" value={this.state.scope.description||""} onChange={(e) => this.changeDescription(e)}/>
                  </div>
                </div>
                <hr/>
                <div className="form-group">
                  <h4>{i18next.t("admin.scope-auth-title")}</h4>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="scope-scheme-password" onChange={(e) => this.togglePasswordRequired(e)} checked={!!this.state.scope.password_required} />
                  <label className="form-check-label" htmlFor="scope-scheme-password">{i18next.t("admin.scope-scheme-password")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" className="input-group-text" htmlFor="scope-password-max-age">{i18next.t("admin.scope-password-max-age")}</label>
                    </div>
                    <input type="number" step="1" min="0" disabled={!this.state.scope.password_required} className="form-control" id="password-max-age" placeholder={i18next.t("admin.scope-password-max-age-ph")} value={this.state.scope.password_max_age||0} onChange={(e) => this.changePwdMaxAge(e)} />
                  </div>
                </div>
                <hr/>
                <div className="form-group">
                  <h4>{i18next.t("admin.scope-auth-schemes-title")}</h4>
                </div>
                <div className="form-group">
                  {groupList}
                  {modSchemeDropdown}
                </div>
              </form>
            </div>
            <div className="modal-footer">
              {hasError}
              <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
              <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
            </div>
          </div>
        </div>
        <input type="file"
               className="upload"
               id="scope-upload"
               onChange={this.getImportScope} />
        <a className="upload" id="scope-download" />
      </div>
		);
	}
}

export default ScopeEdit;
